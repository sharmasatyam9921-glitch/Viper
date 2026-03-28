"""
VIPER 4.0 - API Key Rotation
==============================
Round-robin API key rotation to avoid rate limits.
Thread-safe, counter-based rotation with debug logging.

Usage:
    keys = os.environ.get("SHODAN_API_KEY", "").split(",")
    rotator = KeyRotator(keys, rotate_every_n=10)
    api_key = rotator.current_key
    # ... make request ...
    rotator.tick()
"""

import logging
import threading

logger = logging.getLogger("viper.key_rotation")


class KeyRotator:
    """Rotates through a pool of API keys every N calls."""

    def __init__(self, keys: list, rotate_every_n: int = 10):
        """
        Args:
            keys: List of API key strings. Empty/None entries are filtered out.
            rotate_every_n: Rotate to the next key after this many tick() calls.
        """
        self.keys = [k.strip() for k in keys if k and k.strip()]
        self.rotate_every_n = max(1, rotate_every_n)
        self._call_count = 0
        self._index = 0
        self._lock = threading.Lock()

    @property
    def current_key(self) -> str:
        """Get the current active API key. Returns '' if pool is empty."""
        if not self.keys:
            return ""
        with self._lock:
            return self.keys[self._index % len(self.keys)]

    def tick(self):
        """Call after each API request to advance the rotation counter."""
        if len(self.keys) <= 1:
            return
        with self._lock:
            self._call_count += 1
            if self._call_count >= self.rotate_every_n:
                self._call_count = 0
                old_idx = self._index
                self._index = (self._index + 1) % len(self.keys)
                logger.debug(
                    "Key rotation: switched from index %d to %d (pool size %d)",
                    old_idx, self._index, len(self.keys),
                )

    @property
    def has_keys(self) -> bool:
        """True if at least one valid key is in the pool."""
        return len(self.keys) > 0

    @property
    def pool_size(self) -> int:
        """Number of keys in the rotation pool."""
        return len(self.keys)
