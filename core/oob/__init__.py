"""Out-of-band (OOB) interaction engine — confirm blind vulnerabilities.

The validation gate can confirm reflected/error-based bugs in-band, but *blind*
classes (blind SSRF, blind RCE/command-injection, blind XXE, OAST SQLi, JNDI)
produce no in-band signal. This engine closes that gap: each blind probe embeds a
unique **canary token**; if the target's backend reaches our **listener** (DNS or
HTTP) carrying that token, the interaction is irrefutable proof — the strongest
possible signal, so a gate-confirmed OOB hit is directly submittable.

Usage::

    with OOBServer(base_domain="oob.example", http_port=8080) as oob:
        c = oob.new_canary("ssrf")
        payload = oob.payloads(c)["ssrf"]      # fire this at the target param
        if oob.poll(c.token, timeout=10):      # did the backend call us back?
            ...  # confirmed blind SSRF
"""
from __future__ import annotations

from typing import Dict, Optional

from .canary import Canary, CanaryFactory, payloads_for, new_token  # noqa: F401
from .interaction_server import OOBListeners
from .store import Interaction, InteractionStore   # noqa: F401


class OOBServer:
    def __init__(self, *, base_domain: str = "oob.local",
                 http_host: str = "127.0.0.1", http_port: int = 0,
                 dns_host: str = "127.0.0.1", dns_port: int = 0,
                 enable_dns: bool = True, public_host: Optional[str] = None):
        self.base_domain = base_domain
        # Only interactions for tokens WE issued are ever recorded — the core of
        # correlation integrity. Random / background / legitimate-hex traffic to
        # the listener is dropped, so it can never seed a false confirmation.
        self._issued: set = set()
        self.store = InteractionStore(accept=self._issued.__contains__)
        self._listeners = OOBListeners(
            self.store, http_host=http_host, http_port=http_port,
            dns_host=dns_host, dns_port=dns_port, enable_dns=enable_dns)
        self._public_host = public_host
        self._factory: Optional[CanaryFactory] = None

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> "OOBServer":
        self._listeners.start()
        host = self._public_host or self.base_domain
        base_http = f"http://{host}:{self.http_port}"
        self._factory = CanaryFactory(self.base_domain, base_http)
        return self

    def stop(self) -> None:
        self._listeners.stop()

    def __enter__(self) -> "OOBServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def http_port(self) -> int:
        return self._listeners.http_port

    @property
    def dns_port(self) -> int:
        return self._listeners.dns_port

    # --- API ---------------------------------------------------------------

    def new_canary(self, vuln_type: str = "") -> Canary:
        if self._factory is None:
            raise RuntimeError("OOBServer not started")
        # Mint a FRESH token (regenerate on the astronomically-rare collision /
        # any token that somehow already saw traffic) and register it so the
        # listener will accept its interactions.
        for _ in range(8):
            c = self._factory.new(vuln_type)
            if c.token not in self._issued and not self.store.has_interaction(c.token):
                self._issued.add(c.token)
                return c
        c = self._factory.new(vuln_type)
        self._issued.add(c.token)
        return c

    def issued_count(self) -> int:
        return len(self._issued)

    def payloads(self, canary: Canary) -> Dict[str, str]:
        return payloads_for(canary)

    def was_hit(self, token: str) -> bool:
        return self.store.has_interaction(token)

    def poll(self, token: str, timeout: float = 5.0) -> bool:
        return self.store.poll(token, timeout)

    def interactions_for(self, token: str):
        return self.store.interactions_for(token)

    def summary(self) -> dict:
        return {"base_domain": self.base_domain, "http_port": self.http_port,
                "dns_port": self.dns_port, "interactions": self.store.count()}
