from __future__ import annotations
"""
Main app loop wirring:
Defined session + trace + rendering and exports and menu and then we put it together 
here.
"""

from dataclasses import dataclass
from pathlib import Path

from cryptolab.models.session import SessionState
from cryptolab.io.storage import load_session, save_session, load_trace
from cryptolab.ui.trace import TraceCollector, TraceLevel, TraceStep
from cryptolab.ui.menu import run_menu_loop

@dataclass
class AppConfig:
    trace_level: TraceLevel = TraceLevel.SUMMARY
    code_view: bool = False
    notation_mode: str = "SYMBOLS" # or "EXPANDED"

@dataclass
class AppState:
    session: SessionState
    trace: TraceCollector
    config: AppConfig
    exports_dir: Path
    session_path: Path

def main() -> int:
    root = Path.cwd()
    exports_dir = root / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)

    session_path = exports_dir / "session.json"
    session = load_session(session_path) or SessionState.new()

    state = AppState(
        session=session,
        trace=TraceCollector(),
        config=AppConfig(),
        exports_dir=exports_dir,
        session_path=session_path,
    )
    trace_path = exports_dir / "trace.json"
    for obj in load_trace(trace_path):
        state.trace.add(TraceStep.from_json_obj(obj))


    print("\nCryptoLab booted and UI is ready!\n")

    try: 
        run_menu_loop(state)
    finally:
        save_session(state.session_path, state.session)

    return 0