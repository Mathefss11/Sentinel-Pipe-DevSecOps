"""Safe representation of repository paths in persisted findings (ADR-0010).

File and directory names are repository content: a credential can be committed as a
file name. Raw paths therefore never reach findings, fingerprints or logs without passing
through :func:`safe_paths`. A path component is replaced by a label (``[redacted-N]``)
when either:

* **the scanner flagged it**: Gitleaks scans a worker-generated manifest of the snapshot's
  paths (one per line) with the same ruleset as the content, so every rule that detects a
  secret in content also detects it in a name. Those detections become findings on the
  path (``target = FILE_PATH``); or
* **a heuristic flags it** (defense in depth, for credential formats without a rule): a
  known credential prefix, or a long, high-entropy run of mixed letters and digits.

Labels are assigned per snapshot in the sorted order of the distinct redacted components,
so identical snapshots produce identical safe paths, and therefore identical fingerprints,
without any secret material. The heuristic over-redacts some harmless names, such as
long content hashes; that is the intended failure mode. Neither mechanism can recognize
every possible secret, so redaction of names is best-effort, not a guarantee.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

_TOKEN_RUN = re.compile(r"[A-Za-z0-9+=_\-]{20,}")
_MARKER = re.compile(
    r"(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abposr]-|sk_live_|rk_live_|"
    r"sk-[A-Za-z0-9]|AKIA|ASIA|AIza|-----BEGIN)[A-Za-z0-9+/=_\-]{8,}"
)
MIN_ENTROPY_BITS = 3.5


@dataclass(frozen=True, slots=True)
class SafePath:
    value: str
    redacted: bool


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def suspicious(component: str) -> bool:
    """Whether a path component looks like it contains a credential."""
    if _MARKER.search(component):
        return True
    for match in _TOKEN_RUN.finditer(component):
        run = match.group()
        if (
            any(c.isdigit() for c in run)
            and any(c.isalpha() for c in run)
            and _entropy(run) >= MIN_ENTROPY_BITS
        ):
            return True
    return False


def components_in_byte_window(path: str, start: int, end: int) -> set[int]:
    """Indexes of the components of ``path`` that overlap the UTF-8 byte range
    ``[start, end]`` (0-based, inclusive)."""
    overlapping: set[int] = set()
    offset = 0
    for index, component in enumerate(path.split("/")):
        length = len(component.encode("utf-8"))
        if length and offset <= end and start <= offset + length - 1:
            overlapping.add(index)
        offset += length + 1  # the separator
    return overlapping


def safe_paths(
    paths: Sequence[str], flagged: Mapping[int, Iterable[int]] | None = None
) -> dict[str, SafePath]:
    """Maps every path to its safe representation. ``flagged`` maps a path's index to the
    component indexes the scanner detected; an empty set means "somewhere in this path"
    and redacts every component."""
    marked: dict[str, set[int]] = {}
    for position, path in enumerate(paths):
        parts = path.split("/")
        chosen = {index for index, part in enumerate(parts) if suspicious(part)}
        if flagged is not None and position in flagged:
            detected = set(flagged[position])
            chosen |= detected if detected else set(range(len(parts)))
        marked[path] = chosen
    secrets = sorted(
        {path.split("/")[index] for path, indexes in marked.items() for index in indexes}
    )
    labels = {component: f"[redacted-{number}]" for number, component in enumerate(secrets, 1)}
    result: dict[str, SafePath] = {}
    for path in marked:
        # A redacted component is redacted wherever it occurs, flagged there or not.
        parts = [labels.get(part, part) for part in path.split("/")]
        result[path] = SafePath("/".join(parts), any(part in labels for part in path.split("/")))
    return result
