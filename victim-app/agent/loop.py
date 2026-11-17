import json
import os
from pathlib import Path
from typing import Any

import httpx

from aegis_client import authorize_tool
from agent.identity import AuthenticatedUser, authenticate_user
from tools import load_tools
from tools.registry import REGISTRY, ToolEntry, validate_tool_arguments

ROOT = Path(__file__).resolve().parents[1]
SYSTEM_PROMPT = (ROOT / "agent" / "system_prompt.txt").read_text(encoding="utf-8")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("VICTIM_MODEL", "qwen3:1.7b")
MAX_STEPS = 12


def tool_specs() -> list[dict[str, Any]]:
    load_tools()
    specs = []
    for name, entry in REGISTRY.items():
        description = entry["description"]
        if callable(description):
            description = description()
        specs.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": entry["schema"],
                },
            }
        )
    return specs


def call_tool(
    name: str,
    arguments: dict[str, Any],
    user: AuthenticatedUser,
    sensitive_context: bool = False,
) -> str:
    load_tools()
    if name not in REGISTRY:
        raise ValueError(f"Unknown tool: {name}")
    schema = REGISTRY[name]["schema"]
    error = validate_tool_arguments(arguments, schema)
    if error:
        return f"Error: invalid arguments for {name}; {error}"

    entry: ToolEntry = REGISTRY[name]
    assert isinstance(arguments, dict)
    aegis_decision = authorize_tool(
        tool=name,
        user=user,
        arguments=arguments,
        sensitive_context=sensitive_context,
    )
    if aegis_decision is not None and not aegis_decision["allowed"]:
        return f"Blocked by Aegis: {aegis_decision['reason']}"
    return entry["fn"](**arguments)


def run_agent(
    user_message: str,
    user: AuthenticatedUser,
    max_steps: int = MAX_STEPS,
) -> tuple[str, list[dict[str, Any]]]:
    if max_steps < 1:
        raise ValueError("max_steps must be at least 1")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]
    calls: list[dict[str, Any]] = []
    sensitive_context = False
    with httpx.Client(timeout=180, trust_env=False) as client:
        for _ in range(max_steps):
            response = client.post(
                f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat",
                json={
                    "model": MODEL,
                    "messages": messages,
                    "tools": tool_specs(),
                    "stream": False,
                    "think": False,
                    "options": {
                        "temperature": 0,
                        "num_ctx": 4096,
                        "num_predict": 192,
                    },
                },
            )
            response.raise_for_status()
            assistant_message = response.json()["message"]
            messages.append(assistant_message)

            tool_calls = assistant_message.get("tool_calls", [])
            if not tool_calls:
                return assistant_message.get("content", ""), calls

            for tool_call in tool_calls:
                function = tool_call["function"]
                name = function["name"]
                arguments = function.get("arguments", {})
                result = call_tool(name, arguments, user, sensitive_context)
                calls.append(
                    {"tool": name, "args": arguments, "result": result}
                )
                if REGISTRY[name]["sensitivity"] == "sensitive":
                    sensitive_context = True
                messages.append(
                    {
                        "role": "tool",
                        "tool_name": name,
                        "content": result,
                    }
                )

    return "(stopped: step limit)", calls


if __name__ == "__main__":
    import argparse
    from getpass import getpass

    parser = argparse.ArgumentParser(description="Run the local fake finance assistant")
    parser.add_argument("message", help="What to ask the finance assistant")
    parser.add_argument("--username", choices=("alice", "bob"), required=True)
    args = parser.parse_args()
    user = authenticate_user(args.username, getpass("Victim password: "))
    if user is None:
        parser.error("Victim login failed; check the seeded-user environment settings.")
    answer, tool_calls = run_agent(args.message, user=user)
    print(answer)
    print(json.dumps(tool_calls, indent=2))
