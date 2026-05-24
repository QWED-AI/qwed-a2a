"""
QWED A2A Cryptographic Signing & Verification.

Implements JWT (ES256) attestations for inter-agent payload integrity.
Mirrors the AttestationService pattern from qwed-verification/core/attestation.py.
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class KeyPair:
    """ECDSA P-256 key pair for A2A attestation signing."""

    issuer_id: str
    key_id: str
    _private_key: object = None
    _public_key: object = None

    def __post_init__(self):
        if not HAS_CRYPTO:
            raise RuntimeError(
                "cryptography and PyJWT packages required. "
                "Install with: pip install cryptography PyJWT"
            )
        self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._public_key = self._private_key.public_key()

    @property
    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class A2ACryptoService:
    """
    Handles cryptographic signing and verification for A2A payloads.

    - Signs verification verdicts with ES256 JWT attestations.
    - Verifies incoming agent message signatures.
    - Manages ECDSA P-256 key pairs.
    """

    ALGORITHM = "ES256"
    TOKEN_TYPE = "qwed-a2a-attestation+jwt"

    def __init__(
        self,
        issuer_id: str = "did:qwed:a2a:local",
        validity_seconds: int = 86400,
    ):
        self.issuer_id = issuer_id
        self.validity_seconds = validity_seconds
        self._key_pair: Optional[KeyPair] = None

    def _ensure_key_pair(self) -> KeyPair:
        if self._key_pair is None:
            key_id = f"{self.issuer_id}#signing-key-v1"
            self._key_pair = KeyPair(issuer_id=self.issuer_id, key_id=key_id)
        return self._key_pair

    @staticmethod
    def hash_content(content: str) -> str:
        """Create a deterministic SHA-256 hash of content."""
        return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"

    def sign_verdict(
        self,
        trace_id: str,
        verdict_status: str,
        engine: str,
        sender_id: str,
        receiver_id: str,
        payload_hash: str,
    ) -> str:
        """
        Create a signed JWT attestation for a verification verdict.

        Returns:
            JWT token string.
        """
        key_pair = self._ensure_key_pair()
        now = int(time.time())

        payload = {
            "iss": self.issuer_id,
            "sub": payload_hash,
            "iat": now,
            "exp": now + self.validity_seconds,
            "jti": trace_id,
            "qwed_a2a": {
                "version": "1.0",
                "verdict": verdict_status,
                "engine": engine,
                "sender": sender_id,
                "receiver": receiver_id,
            },
        }

        header = {
            "alg": self.ALGORITHM,
            "typ": self.TOKEN_TYPE,
            "kid": key_pair.key_id,
        }

        return jwt.encode(
            payload,
            key_pair.private_key_pem,
            algorithm=self.ALGORITHM,
            headers=header,
        )

    def verify_attestation(
        self, token: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify a JWT attestation token.

        Returns:
            Tuple of (is_valid, decoded_claims, error_message).
        """
        key_pair = self._ensure_key_pair()

        try:
            claims = jwt.decode(
                token,
                key_pair.public_key_pem,
                algorithms=[self.ALGORITHM],
                options={"require": ["iss", "sub", "iat", "exp", "jti"]},
            )
            return True, claims, None

        except jwt.ExpiredSignatureError:
            return False, None, "Attestation has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {e}"
