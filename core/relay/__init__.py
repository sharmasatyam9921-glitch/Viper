"""Distributed relay — dispatch scoped work to remote worker nodes.

A controller pairs with one or more nodes using a pre-shared key (HMAC-SHA256 on
every message — no asymmetric-crypto dependency; if `cryptography` is installed an
Ed25519 upgrade is a drop-in). The controller dispatches tasks; each node RE-CHECKS
scope server-side and refuses out-of-scope work even if the controller asks for it
— the trust boundary that keeps a compromised/bugged controller from pushing a
node off-scope. Pure stdlib sockets; testable with two local processes.
"""
from __future__ import annotations

from .control import RelayControl  # noqa: F401
from .node import RelayNode  # noqa: F401
from .protocol import sign, verify  # noqa: F401
