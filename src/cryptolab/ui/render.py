from __future__ import annotations

"""
Terminal rendering helper
output that reads easy:
- goal, inputs, steps, outputs, trace, pros, cons, pitfalls, code references (optional)

"""

from typing import Any

def hr() -> str:
    return "-" * 50

def big_title(text: str) -> str:
    return text.upper()

def print_kv_block(title: str, data: Any) -> None:
    print(f"{title}:")
    if isinstance(data, dict):
        for k, v in data.items():
            print(f" - {k}: {v}")
    elif isinstance(data, list):
        for item in data:
            print(f"  - {item}")
    else:
        print(f"  {data}")

def print_numbered_steps(title: str, steps: list[str]) -> None:
    print(f"{title}:")
    for i, step in enumerate(steps, 1):
        print(f" {i}. {step}")