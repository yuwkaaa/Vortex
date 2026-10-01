"""Verbose logging utility for agent execution visualization."""
from __future__ import annotations

from typing import Any, Optional
from datetime import datetime


class VerboseLogger:
    """Logger for tracking agent execution with thought/action/observation/state format."""
    
    def __init__(self):
        self.logs: list[str] = []
    
    def log_node_start(self, node_name: str):
        """Log the start of a node execution."""
        separator = "─" * 80
        self.logs.append(f"\n[NODE]: {node_name}")
        self.logs.append(separator)
    
    def log_thought(self, thought: str):
        """Log agent's thought process."""
        self.logs.append(f"🤔 THOUGHT: {thought}")
    
    def log_action(self, tool_name: str, params: dict[str, Any] | None = None):
        """Log tool invocation with parameters."""
        params_str = ""
        if params:
            params_list = [f"{k}={repr(v)}" for k, v in params.items()]
            params_str = f"({', '.join(params_list)})"
        self.logs.append(f"🛠️  CALLING TOOL: {tool_name}{params_str}")
    
    def log_observation(self, observation: str | dict):
        """Log tool output/observation."""
        if isinstance(observation, dict):
            import json
            observation_text = json.dumps(observation, indent=2, ensure_ascii=False)
        else:
            observation_text = observation
        
        self.logs.append(f"🔌 TOOL OUTPUT:")
        for line in observation_text.split('\n'):
            self.logs.append(f"  {line}")
    
    def log_state_update(self, updates: dict[str, Any]):
        """Log state updates."""
        updates_str = " | ".join([f"{k} = {repr(v)}" for k, v in updates.items()])
        self.logs.append(f"🧠 STATE UPDATE: {updates_str}")
    
    def log_inner_loop_activation(self):
        """Log inner loop activation (syntax/implementation error retry)."""
        self.logs.append("")
        self.logs.append("--- [INNER LOOP ACTIVATED] ---")
        self.logs.append("🤔 RE-THOUGHT: Detecting and fixing implementation error...")
    
    def log_outer_loop_activation(self):
        """Log outer loop activation (strategy change)."""
        self.logs.append("")
        self.logs.append("--- [OUTER LOOP ACTIVATED] ---")
        self.logs.append("🤔 RE-STRATEGY: Changing attack approach due to failed strategy...")
    
    def log_success(self, message: str):
        """Log successful exploitation."""
        self.logs.append("")
        self.logs.append(f"🎯 RESULT: [SUCCESS] {message}")
    
    def log_failure(self, message: str):
        """Log failed exploitation."""
        self.logs.append("")
        self.logs.append(f"❌ RESULT: [FAILED] {message}")
    
    def get_logs(self) -> str:
        """Get all logs as a single string."""
        return "\n".join(self.logs)
    
    def get_logs_list(self) -> list[str]:
        """Get logs as list of lines."""
        return self.logs
    
    def clear(self):
        """Clear all logs."""
        self.logs = []
    
    def __str__(self) -> str:
        return self.get_logs()


def format_node_output(
    node_name: str,
    thought: str,
    action: str,
    observation: str | dict,
    state_updates: dict[str, Any],
) -> str:
    """
    Format node execution output in standard format.
    
    Returns formatted string ready to print.
    """
    logger = VerboseLogger()
    logger.log_node_start(node_name)
    logger.log_thought(thought)
    logger.log_action(action)
    logger.log_observation(observation)
    logger.log_state_update(state_updates)
    return logger.get_logs()
