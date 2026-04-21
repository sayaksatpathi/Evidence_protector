from __future__ import annotations

from pathlib import Path
from typing import List


def tail_lines(path: str, *, max_lines: int, max_bytes: int = 2_000_000) -> List[str]:
    """Return up to the last `max_lines` lines of a text file.

    Cross-platform and safe for very large files by reading from the end.
    """

    if max_lines <= 0:
        return []

    file_path = Path(path)
    with file_path.open("rb") as f:
        f.seek(0, 2)
        end = f.tell()
        to_read = min(max_bytes, end)
        f.seek(end - to_read)
        data = f.read(to_read)

    # Split lines; tolerate unknown encodings.
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()

    # If we started mid-line, drop the first partial line.
    if end > to_read and lines:
        lines = lines[1:]

    if len(lines) <= max_lines:
        return [ln + "\n" for ln in lines]

    tail = lines[-max_lines:]
    return [ln + "\n" for ln in tail]
