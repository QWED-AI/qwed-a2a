# Copyright (c) 2024 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""QWED A2A — Agent-to-Agent Protocol Interceptor."""

__version__ = "0.2.0"

from qwed_a2a.interceptor import A2AVerificationInterceptor
from qwed_a2a.protocol.schema import (
    AgentMessage,
    InterceptorConfig,
    PayloadType,
    VerdictStatus,
    VerificationVerdict,
)

__all__ = [
    "A2AVerificationInterceptor",
    "AgentMessage",
    "InterceptorConfig",
    "PayloadType",
    "VerdictStatus",
    "VerificationVerdict",
]
