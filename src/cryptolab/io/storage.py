from __future__ import annotations

"""
Save/load the session to JSON

Continue works because of the loading of the session and exports/session.json
Write on exit automatically
"""

import json
from pathlib import Path
from typing import Optional

from cryptolab.models.session import SessionState

def load_session(path: Path) -> Optional[SessionState]:
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return SessionState.from_json_obj(obj)
    except Exception:
        #if file is corrupt we just start fresh
        return None

def save_session(path: Path, session: SessionState) -> None:
    path.write_text(json.dumps(session.to_json_obj(), indent=2), encoding="UTF-8")
