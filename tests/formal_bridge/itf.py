import glob
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List


@dataclass(frozen=True)
class ItfState:
    trace_path: str
    index: int
    values: Dict[str, Any]

    @property
    def action(self) -> str:
        return self.values.get("mbt::actionTaken", "")

    def __getitem__(self, key: str) -> Any:
        return self.values[key]


def tag(value: Any) -> Any:
    if isinstance(value, dict) and "tag" in value:
        return value["tag"]
    return value


def option(value: Any) -> Any:
    value_tag = tag(value)
    if value_tag == "None":
        return None
    if value_tag == "Some":
        return value["value"]
    return value


def load_states(pattern: str) -> List[ItfState]:
    states: List[ItfState] = []
    for trace_path in sorted(glob.glob(pattern)):
        with open(trace_path) as trace_file:
            trace = json.load(trace_file)

        for state in trace["states"]:
            states.append(
                ItfState(
                    trace_path=trace_path,
                    index=state["#meta"]["index"],
                    values=state,
                )
            )
    return states


def action_states(pattern: str, action: str) -> Iterable[ItfState]:
    for state in load_states(pattern):
        if state.action == action:
            yield state
