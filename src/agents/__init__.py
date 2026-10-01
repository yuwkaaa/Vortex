from __future__ import annotations

from typing import Any


_EXPORTS = {
    "dual_loop_controller_node": ("src.agents.dual_loop_controller", "dual_loop_controller_node"),
    "executor_node": ("src.agents.executor", "executor_node"),
    "infrastructure_node": ("src.agents.infrastructure", "infrastructure_node"),
    "navigator_node": ("src.agents.navigator", "navigator_node"),
    "planner_node": ("src.agents.planner", "planner_node"),
    "poc_generator_node": ("src.agents.poc_generator", "poc_generator_node"),
}


def __getattr__(name: str) -> Any:
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, attr_name = _EXPORTS[name]
    module = __import__(module_name, fromlist=[attr_name])
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


__all__ = list(_EXPORTS)
