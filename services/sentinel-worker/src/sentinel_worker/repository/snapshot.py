"""Immutable repository snapshots handed to sandboxed scanners as data (ADR-0010).

A scanner never sees a host path. The worker reads the repository content once, validates
it, and builds an in-memory snapshot: an ordered set of regular files with relative POSIX
paths. The snapshot is serialized as a deterministic tar archive and written to the
sandbox's stdin, where it is extracted into the sandbox's own size-limited tmpfs. Nothing
is bind-mounted, so the sandbox cannot reach the source directory, its parents, or any
other host file, and nothing it does can change the source.

Repository content is untrusted. While reading it, the worker:

* never follows symbolic links, Windows junctions or other reparse points (they are
  skipped and counted), so a link cannot pull host files into the snapshot;
* skips hard-linked files (a hard link to a file outside the repository is
  indistinguishable from a regular file by path) and special files (FIFOs, devices,
  sockets), which could block or expose host resources;
* opens files without following links and checks that the opened file is the one it
  inspected (device and inode, type and size), so a file swapped during the walk fails
  the snapshot instead of being read;
* checks that every directory it descends into still resolves inside the root;
* bounds the number of files, the size of each file, the total size, the path length and
  the directory depth; names must be valid UTF-8 without control characters or
  backslashes;
* never executes, interprets or decompresses anything: Git hooks, configuration, build
  files and package manifests are opaque bytes.

Files that are skipped make the snapshot's coverage incomplete; this is reported, never
hidden. Exceeding the file-count or total-size limit fails the snapshot (no silent
truncation).

:class:`LocalFixtureRepositorySource` is the only source in this version: synthetic
repositories in a directory configured on the worker (development and CI). A later
source builds the same snapshot from a verified commit (see ADR-0010).
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from sentinel_worker.execution.leases import JobLease

MAX_FILES = 5000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PATH_BYTES = 1024
MAX_DEPTH = 32

#: Version-control metadata is not part of the working tree that is scanned.
VCS_DIRECTORIES = frozenset({".git"})
#: Repository-controlled scanner suppression files at the root, which scanners would
#: otherwise load from the scanned directory (verified for Gitleaks 8.30.1).
SUPPRESSION_FILES = frozenset({".gitleaksignore"})

_OWNER_OR_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")
_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f-\x9f\\]")
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (Windows)


class SkipReason(StrEnum):
    """Why an entry is not in the snapshot. The first five make coverage incomplete."""

    SYMLINK = "symlink"
    SPECIAL_FILE = "special_file"
    HARDLINK = "hardlink"
    OVERSIZED = "oversized"
    UNSUPPORTED_NAME = "unsupported_name"
    VCS_METADATA = "vcs_metadata"
    SUPPRESSION_FILE = "suppression_file"


#: Skips that leave scannable content out of the snapshot.
INCOMPLETE_COVERAGE = frozenset(
    {
        SkipReason.SYMLINK,
        SkipReason.SPECIAL_FILE,
        SkipReason.HARDLINK,
        SkipReason.OVERSIZED,
        SkipReason.UNSUPPORTED_NAME,
    }
)


class InputErrorCode(StrEnum):
    REPOSITORY_NOT_FOUND = "REPOSITORY_NOT_FOUND"
    REPOSITORY_INVALID = "REPOSITORY_INVALID"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INPUT_CHANGED = "INPUT_CHANGED"
    INPUT_UNREADABLE = "INPUT_UNREADABLE"


class InputError(Exception):
    """The repository input could not be snapshotted. ``code`` is sanitized: no path or
    content is ever part of the message."""

    def __init__(self, code: InputErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    path: str
    """Relative POSIX path (UTF-8, no control characters, no ``..``)."""
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    files: tuple[SnapshotFile, ...]
    """Sorted by path; unique."""
    skipped: Mapping[SkipReason, int]
    kind: str = "LOCAL_FIXTURE"

    def __post_init__(self) -> None:
        """Invariants every source must meet, whatever produced the snapshot: safe,
        unique, sorted relative paths, no path both a file and a directory, bounded."""
        paths = [entry.path for entry in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("snapshot paths must be sorted and unique")
        if len(paths) > MAX_FILES or self.total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("snapshot exceeds the input limits")
        directories: set[str] = set()
        for path in paths:
            parts = path.split("/")
            if (
                not path
                or len(path.encode("utf-8")) > MAX_PATH_BYTES
                or len(parts) > MAX_DEPTH + 1
                or any(not part or not _valid_name(part) for part in parts)
            ):
                raise ValueError("snapshot paths must be safe relative paths")
            directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        if directories & set(paths):
            raise ValueError("a snapshot path cannot be both a file and a directory")

    @property
    def paths(self) -> frozenset[str]:
        return frozenset(entry.path for entry in self.files)

    @property
    def ordered_paths(self) -> tuple[str, ...]:
        return tuple(entry.path for entry in self.files)

    @property
    def extraction_sha256(self) -> str:
        """SHA-256 of the lines ``<sha256(content)>  ./<path>`` (``sha256sum`` format) in
        path order. The sandbox recomputes it from the extracted files, so the scanner
        provably sees exactly these names and bytes."""
        digest = hashlib.sha256()
        for entry in self.files:
            line = f"{hashlib.sha256(entry.content).hexdigest()}  ./{entry.path}\n"
            digest.update(line.encode("utf-8"))
        return digest.hexdigest()

    def path_manifest(self) -> bytes:
        """One path per line, in snapshot order (names contain no line breaks)."""
        return "".join(f"{path}\n" for path in self.ordered_paths).encode("utf-8")

    @property
    def total_bytes(self) -> int:
        return sum(len(entry.content) for entry in self.files)

    @property
    def complete(self) -> bool:
        return not any(self.skipped.get(reason, 0) for reason in INCOMPLETE_COVERAGE)

    @property
    def content_sha256(self) -> str:
        """SHA-256 of the manifest ``path NUL sha256(content) LF`` over all files in path
        order: identifies the scanned content independently of the archive format."""
        digest = hashlib.sha256()
        for entry in self.files:
            digest.update(entry.path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(entry.content).hexdigest().encode("ascii"))
            digest.update(b"\n")
        return digest.hexdigest()

    def archive(self, prefix: str, extra: Mapping[str, bytes] | None = None) -> bytes:
        """A deterministic GNU tar: the files under ``prefix/``, plus worker-controlled
        ``extra`` files (relative paths outside ``prefix``). Only regular files and
        directories; fixed owner, modes and timestamps."""
        buffer = io.BytesIO()
        entries = [(f"{prefix}/{entry.path}", entry.content) for entry in self.files]
        for name, content in (extra or {}).items():
            parts = name.split("/")
            if parts[0] == prefix or any(not part or not _valid_name(part) for part in parts):
                raise ValueError("extra files must be outside the repository prefix")
            entries.append((name, content))
        directories = {prefix}
        for name, _ in entries:
            parts = name.split("/")[:-1]
            directories.update("/".join(parts[: index + 1]) for index in range(len(parts)))
        names = [name for name, _ in entries]
        if len(names) != len(set(names)) or directories & set(names):
            # Never emit an archive in which one entry could overwrite or replace another.
            raise ValueError("archive entries must be unique files")
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for directory in sorted(directories):
                archive.addfile(_member(directory, tarfile.DIRTYPE, 0o755, 0))
            for name, content in sorted(entries):
                archive.addfile(
                    _member(name, tarfile.REGTYPE, 0o644, len(content)), io.BytesIO(content)
                )
        return buffer.getvalue()


def _member(name: str, kind: bytes, mode: int, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.size = size
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


class RepositorySource(Protocol):
    def snapshot(self, lease: JobLease) -> RepositorySnapshot:
        """The content to scan for this job. Raises :class:`InputError`."""
        ...  # pragma: no cover


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        (getattr(info, "st_file_attributes", 0) or 0) & _REPARSE_POINT
    )


def _inside(path: str, root: str) -> bool:
    real = os.path.normcase(os.path.realpath(path))
    return real == root or real.startswith(root + os.sep)


class LocalFixtureRepositorySource:
    """Synthetic repositories under one configured directory (development and CI only).

    A job's repository ``owner/name`` (from the database lease, never from a message)
    selects ``<root>/<owner>/<name>``. Both are validated as GitHub-style names, every
    component must be a real directory (not a link), and the result must resolve inside
    the root, so no lease value can select another host directory.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        path = os.fspath(root)
        if not os.path.isabs(path):
            raise ValueError("the fixture repository root must be an absolute path")
        try:
            info = os.lstat(path)
        except OSError:
            raise ValueError("the fixture repository root does not exist") from None
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("the fixture repository root must be a directory, not a link")
        self._root = os.path.normcase(os.path.realpath(path))

    @property
    def root(self) -> str:
        return self._root

    def snapshot(self, lease: JobLease) -> RepositorySnapshot:
        owner, name = lease.repository.owner, lease.repository.name
        if not all(_OWNER_OR_NAME.match(part) for part in (owner, name)):
            raise InputError(InputErrorCode.REPOSITORY_INVALID)
        current = self._root
        for part in (owner, name):
            current = os.path.join(current, part)
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                raise InputError(InputErrorCode.REPOSITORY_NOT_FOUND) from None
            except OSError:
                raise InputError(InputErrorCode.INPUT_UNREADABLE) from None
            if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                raise InputError(InputErrorCode.REPOSITORY_INVALID)
        if not _inside(current, self._root):
            raise InputError(InputErrorCode.REPOSITORY_INVALID)
        return snapshot_directory(current, self._root)


def snapshot_directory(directory: str, root: str | None = None) -> RepositorySnapshot:
    """Reads ``directory`` into a snapshot under the rules of this module. ``root`` (a
    normalized real path) bounds where descended directories may resolve; it defaults to
    ``directory`` itself."""
    boundary = root if root is not None else os.path.normcase(os.path.realpath(directory))
    walker = _Walker(boundary)
    walker.walk(directory, (), 0)
    files = tuple(sorted(walker.files, key=lambda entry: entry.path))
    return RepositorySnapshot(files=files, skipped=dict(walker.skipped))


class _Walker:
    def __init__(self, boundary: str) -> None:
        self._boundary = boundary
        self.files: list[SnapshotFile] = []
        self.skipped: dict[SkipReason, int] = {}
        self._total = 0

    def _skip(self, reason: SkipReason) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def walk(self, directory: str, parts: tuple[str, ...], depth: int) -> None:
        if not _inside(directory, self._boundary):
            raise InputError(InputErrorCode.INPUT_CHANGED)
        try:
            names = sorted(entry.name for entry in os.scandir(directory))
        except OSError:
            raise InputError(InputErrorCode.INPUT_UNREADABLE) from None
        for name in names:
            path = os.path.join(directory, name)
            try:
                info = os.lstat(path)
            except OSError:
                raise InputError(InputErrorCode.INPUT_CHANGED) from None
            if _is_link(info):
                self._skip(SkipReason.SYMLINK)
                continue
            relative = (*parts, name)
            if not _valid_name(name) or len("/".join(relative).encode("utf-8")) > MAX_PATH_BYTES:
                self._skip(SkipReason.UNSUPPORTED_NAME)
                continue
            if stat.S_ISDIR(info.st_mode):
                if name in VCS_DIRECTORIES:
                    self._skip(SkipReason.VCS_METADATA)
                elif depth + 1 > MAX_DEPTH:
                    self._skip(SkipReason.UNSUPPORTED_NAME)
                else:
                    self.walk(path, relative, depth + 1)
                continue
            if not stat.S_ISREG(info.st_mode):
                self._skip(SkipReason.SPECIAL_FILE)
                continue
            if not parts and name in SUPPRESSION_FILES:
                self._skip(SkipReason.SUPPRESSION_FILE)
                continue
            if info.st_nlink > 1:
                self._skip(SkipReason.HARDLINK)
                continue
            if info.st_size > MAX_FILE_BYTES:
                self._skip(SkipReason.OVERSIZED)
                continue
            if len(self.files) + 1 > MAX_FILES or self._total + info.st_size > MAX_TOTAL_BYTES:
                raise InputError(InputErrorCode.INPUT_TOO_LARGE)
            content = _read(path, info)
            self._total += len(content)
            self.files.append(SnapshotFile("/".join(relative), content))


def _valid_name(name: str) -> bool:
    if _UNSAFE_NAME.search(name) or name in (".", ".."):
        return False
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:  # undecodable bytes on POSIX (surrogate escapes)
        return False
    return True


def _read(path: str, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise InputError(InputErrorCode.INPUT_CHANGED) from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
            or opened.st_size != expected.st_size
        ):
            raise InputError(InputErrorCode.INPUT_CHANGED)
        chunks: list[bytes] = []
        remaining = expected.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise InputError(InputErrorCode.INPUT_UNREADABLE) from None
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if len(content) != expected.st_size:
        raise InputError(InputErrorCode.INPUT_CHANGED)
    return content
