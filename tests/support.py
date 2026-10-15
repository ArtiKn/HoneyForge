import os
import subprocess
import sys
from pathlib import Path


def create_test_certificate(
    directory: Path, *, name: str = "server"
) -> tuple[Path, Path]:
    certificate = directory / f"{name}.crt"
    private_key = directory / f"{name}.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return certificate, private_key


def run_migrations(database_url: str, *arguments: str) -> None:
    """Apply or revert Alembic migrations against one database URL."""

    subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=True,
        env=os.environ | {"DATABASE_URL": database_url},
        capture_output=True,
        text=True,
    )
