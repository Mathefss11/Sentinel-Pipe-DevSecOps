"""Repository snapshots: untrusted filesystem content becomes bounded data (ADR-0010).

Links, hard links, special files and unusual names never pull host content into a
snapshot; the lease's repository identifiers can never select a directory outside the
configured root; limits fail explicitly; errors carry codes, never paths or content.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path

import pytest

from scanner_support import lease, make_repository, synthetic_github_token
from sentinel_worker.repository import snapshot as snapshots
from sentinel_worker.repository.snapshot import (
    InputError,
    InputErrorCode,
    LocalFixtureRepositorySource,
    SkipReason,
    snapshot_directory,
)


def symlink_or_skip(target: Path, link: Path, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("creating symbolic links is not permitted on this host")


def members(archive: bytes) -> list[tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(archive)) as opened:
        return opened.getmembers()


# --- Content and determinism ---------------------------------------------------------


def test_a_snapshot_contains_exactly_the_regular_files(tmp_path: Path) -> None:
    repository = make_repository(
        tmp_path, "repo", {"b.txt": "two", "a/one.py": "print(1)\n", "a/deep/x.json": "{}"}
    )

    snapshot = snapshot_directory(str(repository))

    assert [entry.path for entry in snapshot.files] == ["a/deep/x.json", "a/one.py", "b.txt"]
    assert snapshot.total_bytes == len("two") + len("print(1)\n") + 2
    assert snapshot.complete
    assert snapshot.skipped == {}


def test_snapshots_and_archives_are_deterministic(tmp_path: Path) -> None:
    files = {"z.txt": "z", "dir/a.txt": "a", "ünï cødé.txt": "u"}
    first = snapshot_directory(str(make_repository(tmp_path / "1", "repo", files)))
    second = snapshot_directory(str(make_repository(tmp_path / "2", "repo", files)))

    assert first.content_sha256 == second.content_sha256
    extra = {"config/x.toml": b"x"}
    assert first.archive("repo", extra) == second.archive("repo", extra)
    changed = snapshot_directory(
        str(make_repository(tmp_path / "3", "repo", files | {"z.txt": "Z"}))
    )
    assert changed.content_sha256 != first.content_sha256


def test_archives_hold_only_files_and_directories_with_fixed_metadata(tmp_path: Path) -> None:
    snapshot = snapshot_directory(str(make_repository(tmp_path, "repo", {"a/b.txt": "b"})))

    entries = members(snapshot.archive("repo", {"config/gitleaks.toml": b"[extend]\n"}))

    assert [entry.name for entry in entries] == [
        "config", "repo", "repo/a", "config/gitleaks.toml", "repo/a/b.txt"
    ]  # fmt: skip
    assert all(entry.isfile() or entry.isdir() for entry in entries)
    assert {(entry.uid, entry.gid, entry.mtime, entry.uname) for entry in entries} == {
        (0, 0, 0, "")
    }
    with pytest.raises(ValueError, match="outside"):
        snapshot.archive("repo", {"repo/injected.txt": b"x"})
    with pytest.raises(ValueError, match="outside"):
        snapshot.archive("repo", {"config/../repo/x": b"x"})


def test_unusual_unicode_and_shell_like_names_are_kept_verbatim(tmp_path: Path) -> None:
    names = {
        "ünï cødé.txt": "1",
        "spaces and 'quotes'.txt": "2",
        "$(id);rm -rf x.txt": "3",
        "-leading-dash.txt": "4",
        "rtl-‮txt.exe": "5",
        "日本語/ファイル.md": "6",
    }

    snapshot = snapshot_directory(str(make_repository(tmp_path, "repo", names)))

    assert snapshot.paths == frozenset(names)
    assert snapshot.complete


@pytest.mark.skipif(sys.platform == "win32", reason="Windows forbids these names")
def test_names_with_control_characters_or_backslashes_are_skipped(tmp_path: Path) -> None:
    repository = make_repository(tmp_path, "repo", {"ok.txt": "ok"})
    (repository / "new\nline.txt").write_text("x")
    (repository / "back\\slash.txt").write_text("x")

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"ok.txt"}
    assert snapshot.skipped == {SkipReason.UNSUPPORTED_NAME: 2}
    assert not snapshot.complete


# --- Links, special files, exclusions ------------------------------------------------


def test_symlinks_never_pull_host_files_into_the_snapshot(tmp_path: Path) -> None:
    host_secret = tmp_path / "host-secret.txt"
    host_secret.write_text(f"TOKEN={synthetic_github_token(1)}\n")
    host_directory = tmp_path / "host-directory"
    host_directory.mkdir()
    (host_directory / "inside.txt").write_text("host data")
    repository = make_repository(tmp_path / "fixtures", "repo", {"ok.txt": "ok"})
    symlink_or_skip(host_secret, repository / "escape.txt")
    symlink_or_skip(host_directory, repository / "escape-dir", directory=True)
    symlink_or_skip(Path("../../../host-secret.txt"), repository / "relative-escape.txt")

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"ok.txt"}
    assert snapshot.skipped == {SkipReason.SYMLINK: 3}
    assert not snapshot.complete
    assert synthetic_github_token(1).encode() not in snapshot.archive("repo")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions")
def test_windows_junctions_are_never_followed(tmp_path: Path) -> None:
    import _winapi

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "host.txt").write_text("host data")
    repository = make_repository(tmp_path / "fixtures", "repo", {"ok.txt": "ok"})
    _winapi.CreateJunction(str(outside), str(repository / "junction"))

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"ok.txt"}
    assert snapshot.skipped == {SkipReason.SYMLINK: 1}


def test_hard_links_are_skipped(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("host data")
    repository = make_repository(tmp_path / "fixtures", "repo", {"ok.txt": "ok"})
    os.link(outside, repository / "hardlink.txt")

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"ok.txt"}
    assert snapshot.skipped == {SkipReason.HARDLINK: 1}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
def test_special_files_are_skipped_without_blocking(tmp_path: Path) -> None:
    repository = make_repository(tmp_path, "repo", {"ok.txt": "ok"})
    os.mkfifo(repository / "pipe")

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"ok.txt"}
    assert snapshot.skipped == {SkipReason.SPECIAL_FILE: 1}


def test_vcs_metadata_and_root_suppression_files_are_excluded_by_design(tmp_path: Path) -> None:
    repository = make_repository(
        tmp_path,
        "repo",
        {
            ".git/config": "[core]\n",
            ".git/hooks/post-checkout": "#!/bin/sh\necho never executed\n",
            ".gitleaksignore": "app.py:github-pat:1\n",
            "nested/.gitleaksignore": "kept: only the root file is loaded by Gitleaks\n",
            ".gitleaks.toml": "kept: overridden by the worker's --config\n",
            "app.py": "x",
        },
    )

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"app.py", "nested/.gitleaksignore", ".gitleaks.toml"}
    assert snapshot.skipped == {SkipReason.VCS_METADATA: 1, SkipReason.SUPPRESSION_FILE: 1}
    assert snapshot.complete


# --- Limits --------------------------------------------------------------------------


def test_oversized_files_are_skipped_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(snapshots, "MAX_FILE_BYTES", 10)
    repository = make_repository(tmp_path, "repo", {"small.txt": "1234", "big.bin": "x" * 11})

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"small.txt"}
    assert snapshot.skipped == {SkipReason.OVERSIZED: 1}
    assert not snapshot.complete


@pytest.mark.parametrize(
    ("limit", "value"), [("MAX_FILES", 2), ("MAX_TOTAL_BYTES", 5)], ids=["files", "bytes"]
)
def test_exceeding_the_input_limits_fails_explicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str, value: int
) -> None:
    monkeypatch.setattr(snapshots, limit, value)
    repository = make_repository(tmp_path, "repo", {"a": "123", "b": "456", "c": "789"})

    with pytest.raises(InputError) as raised:
        snapshot_directory(str(repository))

    assert raised.value.code is InputErrorCode.INPUT_TOO_LARGE
    assert str(raised.value) == "INPUT_TOO_LARGE"


def test_deep_nesting_and_long_paths_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(snapshots, "MAX_DEPTH", 2)
    monkeypatch.setattr(snapshots, "MAX_PATH_BYTES", 20)
    repository = make_repository(
        tmp_path, "repo", {"a/b/c/deep.txt": "x", "a/ok.txt": "x", "long-" * 5 + ".txt": "x"}
    )

    snapshot = snapshot_directory(str(repository))

    assert snapshot.paths == {"a/ok.txt"}
    assert snapshot.skipped == {SkipReason.UNSUPPORTED_NAME: 2}


# --- The local fixture source: lease values never select host directories ------------


def test_the_fixture_source_selects_owner_and_name_under_its_root(tmp_path: Path) -> None:
    make_repository(tmp_path, "repo", {"a.txt": "a"})

    snapshot = LocalFixtureRepositorySource(tmp_path).snapshot(lease("repo"))

    assert snapshot.paths == {"a.txt"}
    assert snapshot.kind == "LOCAL_FIXTURE"


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        ("acme", ".."),
        ("..", "repo"),
        ("acme", "../../etc"),
        ("acme", "a/b"),
        ("acme", "a\\b"),
        ("acme", ".hidden"),
        ("acme", "C:"),
        ("acme", ""),
        ("acme", "x" * 101),
        ("/etc", "passwd"),
    ],
)
def test_lease_repository_values_cannot_escape_the_root(
    tmp_path: Path, owner: str, name: str
) -> None:
    make_repository(tmp_path, "repo", {"a.txt": "a"})

    with pytest.raises(InputError) as raised:
        LocalFixtureRepositorySource(tmp_path).snapshot(lease(name, owner=owner))

    assert raised.value.code is InputErrorCode.REPOSITORY_INVALID


def test_an_unknown_repository_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputError) as raised:
        LocalFixtureRepositorySource(tmp_path).snapshot(lease("missing"))

    assert raised.value.code is InputErrorCode.REPOSITORY_NOT_FOUND


def test_a_linked_repository_directory_is_refused(tmp_path: Path) -> None:
    host = tmp_path / "host"
    host.mkdir()
    (host / "data.txt").write_text("host data")
    root = tmp_path / "fixtures"
    (root / "acme").mkdir(parents=True)
    symlink_or_skip(host, root / "acme" / "repo", directory=True)

    with pytest.raises(InputError) as raised:
        LocalFixtureRepositorySource(root).snapshot(lease("repo"))

    assert raised.value.code is InputErrorCode.REPOSITORY_INVALID


def test_the_fixture_root_must_be_an_absolute_real_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        LocalFixtureRepositorySource("relative/fixtures")
    with pytest.raises(ValueError, match="exist"):
        LocalFixtureRepositorySource(tmp_path / "missing")
    (tmp_path / "file").write_text("x")
    with pytest.raises(ValueError, match="directory"):
        LocalFixtureRepositorySource(tmp_path / "file")
    target = tmp_path / "real"
    target.mkdir()
    symlink_or_skip(target, tmp_path / "link", directory=True)
    with pytest.raises(ValueError, match="link"):
        LocalFixtureRepositorySource(tmp_path / "link")


def test_a_file_swapped_during_the_read_fails_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = make_repository(tmp_path, "repo", {"a.txt": "original"})
    real_lstat = os.lstat

    def stale_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        info = real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]
        if str(path).endswith("a.txt"):
            # The file inspected is not the file that will be opened.
            values = list(info)
            values[6] = info.st_size + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(snapshots.os, "lstat", stale_lstat)

    with pytest.raises(InputError) as raised:
        snapshot_directory(str(repository))

    assert raised.value.code is InputErrorCode.INPUT_CHANGED
    assert str(tmp_path) not in str(raised.value)
