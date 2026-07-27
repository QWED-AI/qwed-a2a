"""
Shared setup for the qwed-a2a benchmark suite.

Environment variables MUST be set before importing qwed_a2a modules because
crypto.py reads QWED_A2A_DEPLOYMENT_ID and QWED_A2A_SIGNING_KEY_PEM at module
import time. This mirrors the setup used by the test conftest so benchmarks
run against a realistic, deterministic key pair.
"""

import os

os.environ.setdefault("QWED_A2A_DEPLOYMENT_ID", "qwed-a2a-benchmark-deployment")

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_bench_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
_bench_signing_key_pem = _bench_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
os.environ.setdefault("QWED_A2A_SIGNING_KEY_PEM", _bench_signing_key_pem)
