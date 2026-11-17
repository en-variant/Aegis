import os
from typing import Any

import httpx

from agent.identity import AuthenticatedUser, mint_identity_token


def authorize_tool(
    *,
    tool: str,
    user: AuthenticatedUser | None,
    arguments: dict[str, Any],
    sensitive_context: bool,
) -> dict[str, Any] | None:
    base_url = os.environ.get("AEGIS_URL", "").rstrip("/")
    token = os.environ.get("AEGIS_APP_TOKEN", "")
    if not base_url and not token:
        return None
    if not base_url or not token:
        raise RuntimeError(
            "Set both AEGIS_URL and AEGIS_APP_TOKEN, or unset both for standalone mode"
        )
    if user is None:
        raise RuntimeError("A signed-in Victim user is required for Aegis authorization")
    try:
        identity_token = mint_identity_token(user)
    except (OSError, RuntimeError):
        raise RuntimeError(
            "Victim identity signing is not configured; tool action was not run"
        ) from None

    try:
        response = httpx.post(
            f"{base_url}/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Aegis-Identity": identity_token,
            },
            json={
                "tool": tool,
                "arguments": arguments,
                "sensitive_context": sensitive_context,
            },
            timeout=10,
            trust_env=False,
        )
    except httpx.HTTPError:
        raise RuntimeError(
            "Aegis authorization service is unavailable; tool action was not run"
        ) from None
    if response.status_code in {401, 403}:
        raise RuntimeError("Aegis rejected the victim application credentials")
    response.raise_for_status()
    result = response.json()
    if type(result.get("allowed")) is not bool or not isinstance(
        result.get("reason"), str
    ):
        raise RuntimeError("Aegis returned an invalid authorization decision")
    return result
