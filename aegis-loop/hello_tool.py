import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

api_url = f"{os.environ['OLLAMA_BASE_URL'].rstrip('/')}/api/chat"
model = os.environ["OLLAMA_MODEL"]

tools = [
    {
        "type": "function",
        "function": {
            "name": "add",
            "description": "Add two numbers and return their sum.",
            "parameters": {
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                },
                "required": ["a", "b"],
            },
        },
    }
]

messages = [{"role": "user", "content": "Use the add tool to calculate 17 + 25."}]
tool_was_used = False

with httpx.Client(timeout=180, trust_env=False) as client:
    for _ in range(5):
        response = client.post(
            api_url,
            json={
                "model": model,
                "messages": messages,
                "tools": tools,
                "stream": False,
                "think": False,
                "options": {"temperature": 0},
            },
        )
        response.raise_for_status()
        assistant_message = response.json()["message"]
        messages.append(assistant_message)

        tool_calls = assistant_message.get("tool_calls", [])
        if not tool_calls:
            answer = assistant_message.get("content", "")
            if not tool_was_used:
                raise RuntimeError("The model answered without using the add tool.")
            if "42" not in answer:
                raise RuntimeError(f"The final answer did not contain 42: {answer!r}")
            print(answer)
            break

        for call in tool_calls:
            function = call["function"]
            if function["name"] != "add":
                raise RuntimeError(f"Unexpected tool requested: {function['name']}")
            arguments = function["arguments"]
            total = arguments["a"] + arguments["b"]
            messages.append(
                {
                    "role": "tool",
                    "tool_name": function["name"],
                    "content": str(total),
                }
            )
            tool_was_used = True
    else:
        raise RuntimeError("The model did not finish within five tool-call steps.")
