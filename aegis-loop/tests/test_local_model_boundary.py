import pytest

from aegis_loop.runtime import validate_local_model_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434",
        "http://localhost:11434/",
        "http://[::1]:11434",
    ],
)
def test_local_ollama_urls_are_allowed(url: str) -> None:
    assert validate_local_model_url(url).startswith("http")


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://192.0.2.10:11434",
        "http://user:password@localhost:11434",
        "file:///tmp/ollama",
    ],
)
def test_remote_or_malformed_model_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="Ollama"):
        validate_local_model_url(url)
