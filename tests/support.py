import asyncio
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


async def read_packet(reader):
    header = await asyncio.wait_for(reader.readexactly(4), 2)
    return header[3], await reader.readexactly(int.from_bytes(header[:3], 'little'))


async def write_packet(writer, payload, sequence=0):
    writer.write(len(payload).to_bytes(3, 'little') + bytes([sequence]) + payload)
    await writer.drain()


async def mysql_login(port, username='admin', password='secret'):
    from agent.medium.mysql_service import MediumMySqlService
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    sequence, handshake = await read_packet(reader)
    assert sequence == 0 and handshake[0] == 10
    offset = handshake.index(b'\x00', 1) + 5
    nonce = handshake[offset:offset + 8] + handshake[offset + 27:offset + 39]
    assert len(nonce) == 20
    flags = 1 | 512 | 32768 | 524288 | 2097152
    response = MediumMySqlService.native_response(password, nonce)
    packet = flags.to_bytes(4, 'little') + (65536).to_bytes(4, 'little') + b'\x21' + b'\x00' * 23
    packet += username.encode() + b'\x00' + bytes([len(response)]) + response + b'mysql_native_password\x00'
    await write_packet(writer, packet, 1)
    sequence, result = await read_packet(reader)
    assert sequence == 2
    return reader, writer, result


async def mysql_query(reader, writer, sql):
    await write_packet(writer, b'\x03' + sql.encode())
    sequence, first = await read_packet(reader)
    assert sequence == 1
    if first[0] in (0, 255):
        return [first]
    for _ in range(first[0]):
        await read_packet(reader)  # column definitions
    _, eof = await read_packet(reader)
    assert eof[0] == 254
    rows = []
    while True:
        _, packet = await read_packet(reader)
        if packet[0] == 254:
            return rows
        rows.append(packet)
