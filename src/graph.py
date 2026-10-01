from __future__ import annotations

import os
from typing import Literal

from langgraph.graph import END, StateGraph

from src.agents import (
    dual_loop_controller_node,
    executor_node,
    infrastructure_node,
    navigator_node,
    planner_node,
    poc_generator_node,
)
from src.metrics import timed_node
from src.state import PentestState


DualRoute = Literal["poc_generator", "executor", "planner", "fail"]
InfraRoute = Literal["planner", "executor", "fail"]


def _route_entry(state: PentestState) -> Literal["infrastructure", "planner", "navigator", "executor"]:
    """
    Case A (target_path set)  → Infrastructure → Planner → Navigator → Executor
    Case B (target_url, known vuln type) → Planner → Navigator → Executor
    Case C (black-box / unknown vuln type) → Navigator (discovery) → Planner → Navigator → Executor
    Single-Agent baseline (ABLATE_MULTI_AGENT=1) → bypasses Planner/Navigator/Dual-Loop directly to Executor.
    """
    if state.get("target_path"):
        return "infrastructure"
    if os.getenv("ABLATE_MULTI_AGENT") == "1":
        return "executor"
    vt = (state.get("cve_config") or {}).get("vulnerability_type", "")
    if state.get("discovery_mode") or not vt or vt.lower() == "unknown":
        return "navigator"  # Case C: discover first
    return "planner"


def _route_from_navigator(state: PentestState) -> Literal["planner", "executor"]:
    """
    After discovery mode: route to Planner so it can build a plan.
    After normal recon  : route directly to Executor.
    """
    if state.get("status") == "discovery_done":
        return "planner"
    return "executor"


def _route_from_infrastructure(state: PentestState) -> InfraRoute:
    """
    Infrastructure failure is terminal.

    If Docker cannot build/start/resolve a target URL, planner/navigator/executor
    cannot do useful work. Route directly to the report generator so the fatal
    root cause is visible instead of being hidden behind repeated planner loops.
    """
    if state.get("status") == "failed" or not state.get("target_url"):
        return "fail"
    if os.getenv("ABLATE_MULTI_AGENT") == "1":
        return "executor"
    return "planner"


def _route_from_executor(state: PentestState) -> Literal["dual_loop", "poc_generator"]:
    """In single-agent baseline mode, terminate after the single execution loop."""
    if os.getenv("ABLATE_MULTI_AGENT") == "1":
        return "poc_generator"
    return "dual_loop"


def _route_from_dual_loop(state: PentestState) -> DualRoute:
    decision = state.get("dual_loop_decision", "planner")
    if decision in ("poc_generator", "executor", "planner", "fail"):
        return decision
    return "planner"


def build_graph():
    """
    Execution flow:

      Case A (--target-path):
        Infrastructure → Planner → Navigator → Executor
          → Dual-Loop (≤3 iterations)

      Case B (--target-url, known vuln):
        Planner → Navigator → Executor
          → Dual-Loop (≤3 iterations)

      Case C (--target-url, black-box / unknown vuln):
        Navigator [discovery] → Planner → Navigator [recon] → Executor
          → Dual-Loop (≤3 iterations)

      All paths converge at Dual-Loop → (inner: Executor | outer: Planner | success: PoC Generator)
    """
    g = StateGraph(PentestState)

    g.add_node("infrastructure", timed_node("infrastructure", infrastructure_node))
    g.add_node("planner", timed_node("planner", planner_node))
    g.add_node("navigator", timed_node("navigator", navigator_node))
    g.add_node("executor", timed_node("executor", executor_node))
    g.add_node("dual_loop", timed_node("dual_loop", dual_loop_controller_node))
    g.add_node("poc_generator", timed_node("poc_generator", poc_generator_node))

    # Entry: Case A / B / C / Single-Agent
    g.set_conditional_entry_point(
        _route_entry,
        {
            "infrastructure": "infrastructure",
            "planner": "planner",
            "navigator": "navigator",
            "executor": "executor",
        },
    )

    g.add_conditional_edges(
        "infrastructure",
        _route_from_infrastructure,
        {
            "planner": "planner",
            "executor": "executor",
            "fail": "poc_generator",
        },
    )
    g.add_edge("planner", "navigator")

    # Navigator routes to planner (after discovery) or executor (after normal recon)
    g.add_conditional_edges(
        "navigator",
        _route_from_navigator,
        {
            "planner": "planner",
            "executor": "executor",
        },
    )

    g.add_conditional_edges(
        "executor",
        _route_from_executor,
        {
            "dual_loop": "dual_loop",
            "poc_generator": "poc_generator",
        },
    )

    g.add_conditional_edges(
        "dual_loop",
        _route_from_dual_loop,
        {
            "poc_generator": "poc_generator",
            "executor": "executor",
            "planner": "planner",
            "fail": "poc_generator",
        },
    )

    g.add_edge("poc_generator", END)

    return g.compile()
