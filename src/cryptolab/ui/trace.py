from __future__ import annotations
"""
Every module run creates TraceStep records describing the following:
    -Goal, Inputs, Algorithm steps, outputs, trace details: summary and full

Demonstrates the step by step outputs of each function and a user-friednly interface in a way
that is consistent and easy to understand.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

class TraceLevel(str, Enum):
    OFF = "OFF"
    SUMMARY = "SUMMARY"
    FULL = "FULL"

    def next(self) -> "TraceLevel":
        order = [TraceLevel.OFF, TraceLevel.SUMMARY, TraceLevel.FULL]
        return order[(order.index(self) + 1) % len(order)] # order and index to cycle through levels

@dataclass
# A single step in the trace, representing the execution of a module or function with its inputs, outputs, and details.
class TraceStep:
    module: str
    title: str

    goal: str
    inputs: Dict[str, Any] = field(default_factory=dict)

    algorithm_steps: List[str] = field(default_factory=list)
    outputs: Dict[str, Any] = field(default_factory=dict)

    trace_sumamry: List[str] = field(default_factory=list)
    trace_full: List[str] = field(default_factory=list)

    pros: List[str] = field(default_factory=list)
    cons: List[str] = field(default_factory=list)
    pitfalls: List[str] = field(default_factory=list)

    code_ref: List[str] = field(default_factory=list) # list of code references for this step, e.g. ["rsa.py:generate_keys"]


class TraceCollector:
    # Collects TraceStep records for the current session, allowing for adding new steps and retrieving the trace history.
    def __init__(self) -> None:
        self._steps: List[TraceStep] = []
    
    def clear(self) -> None:
        self._steps.clear()
    def add(self, step: TraceStep) -> None:
        self._steps.append(step)
    def steps(self) -> List[TraceStep]:
        return self._steps
    def is_empty(self) -> bool:
        return len(self._steps) == 0

