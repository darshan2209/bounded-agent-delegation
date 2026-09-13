"""JWT helpers for the laboratory.

RS256 with an ephemeral keypair generated at start-up. Nothing here is a secret
worth protecting: the keypair exists so that the experiment exercises real
signature verification rather than a stub, and it is discarded on shutdown.
"""
from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_ALG = "RS256"
_KID = "lab-key-1"


class KeyPair:
    """An ephemeral RSA keypair shared by the IdP, the broker and the resources."""

    def __init__(self) -> None:
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.public_pem = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, claims: dict) -> str:
        return jwt.encode(claims, self.private_pem, algorithm=_ALG,
                          headers={"kid": _KID})

    def verify(self, token: str, audience: str | None = None) -> dict:
        """Decode and verify. Raises jwt.PyJWTError on any failure."""
        return jwt.decode(
            token,
            self.public_pem,
            algorithms=[_ALG],
            audience=audience,
            options={"require": ["exp", "iat", "sub", "aud"],
                     "verify_aud": audience is not None},
        )


def mint(keys: KeyPair, *, subject: str, audience: str | list[str], scope: list[str],
         ttl_seconds: int, actor: str | None = None, may_act: str | None = None,
         issuer: str = "https://idp.lab/") -> str:
    """Build and sign an access token.

    `actor` populates the RFC 8693 `act` claim, which records that delegation
    occurred and names the acting party. `may_act` pre-authorises who is
    permitted to act for this subject.
    """
    now = int(time.time())
    claims: dict = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "scope": " ".join(scope),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
    }
    if actor:
        # RFC 8693 section 4.1: the act claim names the current actor.
        claims["act"] = {"sub": actor}
    if may_act:
        # RFC 8693 section 4.4: may_act states who may become the actor.
        claims["may_act"] = {"sub": may_act}
    return keys.sign(claims)


def scopes_of(claims: dict) -> set[str]:
    return set(str(claims.get("scope", "")).split())


def audiences_of(claims: dict) -> set[str]:
    aud = claims.get("aud", [])
    if isinstance(aud, str):
        return {aud}
    return set(aud)


def seconds_remaining(claims: dict) -> int:
    return int(claims.get("exp", 0)) - int(time.time())
