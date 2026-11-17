import pytest


@pytest.fixture(autouse=True)
def app_token_pepper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "AEGIS_TOKEN_PEPPER",
        "test-only-aegis-token-pepper-at-least-32-bytes",
    )
