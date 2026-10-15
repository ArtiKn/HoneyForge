import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from center.api.models import AuditEntry, Operator

PASSWORD_SCHEME = "scrypt"
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SESSION_ISSUER = "honeyforge-control-center"
ROLE_ADMIN = "admin"
DUMMY_PASSWORD_HASH = "$".join(
    (
        PASSWORD_SCHEME,
        str(SCRYPT_N),
        str(SCRYPT_R),
        str(SCRYPT_P),
        base64.urlsafe_b64encode(bytes(16)).rstrip(b"=").decode(),
        base64.urlsafe_b64encode(
            hashlib.scrypt(
                b"invalid-password",
                salt=bytes(16),
                n=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P,
            )
        )
        .rstrip(b"=")
        .decode(),
    )
)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    )
    return "$".join(
        (
            PASSWORD_SCHEME,
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            _encode(salt),
            _encode(digest),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = encoded.split("$", 5)
        if scheme != PASSWORD_SCHEME:
            return False
        actual = hashlib.scrypt(
            password.encode(),
            salt=_decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
        )
        return hmac.compare_digest(actual, _decode(expected))
    except (ValueError, TypeError):
        return False


def create_session_token(operator: Operator, secret: str, lifetime_seconds: int) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(operator.id),
        "iss": SESSION_ISSUER,
        "iat": now,
        "exp": now + lifetime_seconds,
        "ver": operator.session_version,
    }
    signing_input = f"{_encode_json(header)}.{_encode_json(payload)}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_encode(signature)}"


def read_session_claims(token: str, secret: str) -> tuple[UUID, int] | None:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".", 2)
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _decode(encoded_signature)):
            return None
        header = json.loads(_decode(encoded_header))
        payload = json.loads(_decode(encoded_payload))
        if header != {"alg": "HS256", "typ": "JWT"}:
            return None
        if payload.get("iss") != SESSION_ISSUER or int(payload["exp"]) <= int(time.time()):
            return None
        session_version = int(payload["ver"])
        if session_version < 0:
            return None
        return UUID(payload["sub"]), session_version
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


async def seed_operator(
    session_factory: async_sessionmaker[AsyncSession],
    username: str,
    password: str,
    role: str = ROLE_ADMIN,
) -> None:
    async with session_factory() as session:
        operator = await session.scalar(
            select(Operator).where(Operator.username == username)
        )
        if operator is None:
            operator = Operator(
                username=username,
                password_hash=hash_password(password),
                role=role,
                is_active=True,
                session_version=0,
            )
            session.add(operator)
        else:
            if not verify_password(password, operator.password_hash):
                operator.password_hash = hash_password(password)
                operator.session_version += 1
            operator.role = role
        await session.commit()


async def authenticate(
    session: AsyncSession,
    username: str,
    password: str,
    source_ip: str | None,
) -> Operator | None:
    operator = await session.scalar(select(Operator).where(Operator.username == username))
    candidate_hash = (
        operator.password_hash
        if operator is not None and operator.is_active
        else DUMMY_PASSWORD_HASH
    )
    password_matches = verify_password(password, candidate_hash)
    valid = operator is not None and operator.is_active and password_matches
    session.add(
        AuditEntry(
            operator_id=operator.id if operator else None,
            action="operator.login.succeeded" if valid else "operator.login.failed",
            entity="operator",
            entity_id=operator.id if operator else None,
            details={} if valid else {"username": username},
            source_ip=source_ip,
        )
    )
    if not valid:
        await session.commit()
        return None
    operator.last_login_at = datetime.now(UTC)
    return operator


async def operator_for_session(
    session: AsyncSession, token: str | None, secret: str
) -> Operator | None:
    claims = read_session_claims(token, secret) if token else None
    if claims is None:
        return None
    operator_id, session_version = claims
    operator = await session.get(Operator, operator_id)
    if (
        operator is None
        or not operator.is_active
        or operator.session_version != session_version
    ):
        return None
    return operator


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode_json(value: dict[str, object]) -> str:
    return _encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())
