from __future__ import annotations

import json
import re
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CanaryToken:
    version: int
    id: str
    created_at: str
    token: str
    hint: str


def generate_canary(*, hint: str = "") -> CanaryToken:
    token = secrets.token_urlsafe(18)
    return CanaryToken(version=1, id=uuid.uuid4().hex, created_at=_now_utc_iso(), token=token, hint=hint)


def save_canary(canary: CanaryToken, path: str) -> None:
    Path(path).write_text(json.dumps(asdict(canary), indent=2) + "\n", encoding="utf-8")


def load_canary(path: str) -> CanaryToken:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return CanaryToken(**raw)


def scan_for_canary(file_path: str, token: str, *, max_matches: int = 50) -> List[Tuple[int, str]]:
    matches: List[Tuple[int, str]] = []
    pat = re.compile(re.escape(token))
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if pat.search(line):
                matches.append((line_no, line.rstrip("\n")))
                if len(matches) >= max_matches:
                    break
    return matches
