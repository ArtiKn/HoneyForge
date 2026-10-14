import subprocess
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
