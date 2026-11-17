from __future__ import annotations

import argparse
import base64
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT.parent / "victim-app" / ".identity" / "aegis-ed25519.pem"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an Ed25519 Aegis end-user identity keypair."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"private key output path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    output: Path = args.output.expanduser().resolve()
    if output.exists():
        parser.error(f"refusing to overwrite existing private key: {output}")

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        parser.error(f"refusing to overwrite existing private key: {output}")
    with os.fdopen(descriptor, "wb") as private_file:
        private_file.write(private_bytes)

    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    encoded_public_key = base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("=")
    print(f"Private key written to: {output}")
    print(f"kid: aegis-{secrets.token_urlsafe(9)}")
    print(f"public_key: {encoded_public_key}")
    print("Register the kid and public_key in the Aegis dashboard for the app.")
    print("Keep the private key local; never paste it into the LLM prompt or commit it.")


if __name__ == "__main__":
    main()
