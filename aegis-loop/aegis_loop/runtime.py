import importlib
import ipaddress
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit

from aegis_loop import events, policy
from aegis_loop.config import VICTIM_ROOT

target_loop: ModuleType | None = None
_victim_call_tool: Any = None
_reset_victim_data: Any = None
_registry: dict[str, Any] | None = None


def _load_local_target() -> ModuleType:
    global target_loop, _victim_call_tool, _reset_victim_data, _registry
    if target_loop is not None:
        return target_loop
    if not VICTIM_ROOT.is_dir():
        raise FileNotFoundError(
            f"Local victim app directory not found: {VICTIM_ROOT}. "
            "Set AEGIS_VICTIM_PATH for local demo commands."
        )
    if str(VICTIM_ROOT) not in sys.path:
        sys.path.insert(0, str(VICTIM_ROOT))
    target_loop = importlib.import_module("agent.loop")
    tools_package = importlib.import_module("tools")
    tools_package.load_tools()
    registry_module = importlib.import_module("tools.registry")
    _registry = registry_module.REGISTRY
    if not hasattr(target_loop, "_aegis_unwrapped_call_tool"):
        target_loop._aegis_unwrapped_call_tool = target_loop.call_tool
    _victim_call_tool = target_loop._aegis_unwrapped_call_tool
    _reset_victim_data = importlib.import_module("reset").reset_data
    return target_loop


def validate_local_model_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Ollama URL must use HTTP(S) and a loopback host")
    if parsed.username or parsed.password:
        raise ValueError("Ollama URL must not include credentials")
    try:
        is_local = parsed.hostname.casefold() == "localhost" or ipaddress.ip_address(
            parsed.hostname
        ).is_loopback
    except ValueError:
        is_local = False
    if not is_local:
        raise ValueError("Ollama must run on this computer; remote model URLs are disabled")
    return url.rstrip("/")


def install() -> None:
    """Install Aegis at the victim's generic tool-call seam."""
    _load_local_target().call_tool = call_tool


def call_tool(
    name: str,
    arguments: dict[str, Any],
    role: str,
    sensitive_context: bool = False,
) -> str:
    _load_local_target()
    assert _registry is not None
    if name not in _registry:
        raise ValueError(f"Unknown tool: {name}")
    validate_arguments = importlib.import_module(
        "tools.registry"
    ).validate_tool_arguments
    schema = _registry[name]["schema"]
    error = validate_arguments(arguments, schema)
    if error:
        reason = f"invalid arguments: {error}"
        result = f"Error: invalid arguments for {name}; {error}"
        redacted_arguments = policy.sanitize_event_arguments(arguments)
        if not isinstance(redacted_arguments, dict):
            redacted_arguments = {"arguments": redacted_arguments}
        events.log_tool_event(
            role=role,
            tool_name=name,
            arguments=redacted_arguments,
            result=result,
            allowed=False,
            reason=reason,
        )
        return result
    assert isinstance(arguments, dict)

    decision = policy.guard_hook(name, arguments, role)
    if sensitive_context and name in {"send_email", "post_chat"}:
        decision = {
            "allowed": False,
            "reason": "sensitive source data cannot be sent externally",
        }
    if (
        not isinstance(decision, dict)
        or type(decision.get("allowed")) is not bool
        or not isinstance(decision.get("reason"), str)
    ):
        decision = {
            "allowed": False,
            "reason": "Aegis policy returned an invalid decision",
        }
    allowed = decision["allowed"]
    reason = decision["reason"]
    if not allowed:
        result = f"Blocked by Aegis: {reason}"
        events.log_tool_event(
            role=role,
            tool_name=name,
            arguments=arguments,
            result=result,
            allowed=False,
            reason=reason,
            redacted_arguments=policy.sanitize_event_arguments(arguments),
            redacted_result=policy.sanitize_event_value(result),
        )
        return result

    assert _victim_call_tool is not None
    result = _victim_call_tool(name, arguments, role)
    events.log_tool_event(
        role=role,
        tool_name=name,
        arguments=arguments,
        result=result,
        allowed=True,
        reason=reason,
        redacted_arguments=policy.sanitize_event_arguments(arguments),
        redacted_result=policy.sanitize_event_value(result),
    )
    return result


def run_agent(
    user_message: str,
    role: str = "employee",
    max_steps: int = 12,
) -> tuple[str, list[dict[str, Any]]]:
    target = _load_local_target()
    install()
    importlib.reload(target)
    install()
    validate_local_model_url(
        os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    )
    return target.run_agent(user_message, role=role, max_steps=max_steps)


def reset_demo() -> None:
    _load_local_target()
    assert _reset_victim_data is not None
    _reset_victim_data()


def target_file(relative_path: str) -> Path:
    path = (VICTIM_ROOT / relative_path).resolve(strict=True)
    if not path.is_relative_to(VICTIM_ROOT):
        raise ValueError("Target path must remain inside victim-app")
    return path
