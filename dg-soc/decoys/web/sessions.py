"""Bounded, process-local synthetic sessions; never log the bearer cookie.

The deployed web decoy deliberately uses one Gunicorn worker. Restarting that
worker invalidates sessions. These are lab identities, not institutional users.
"""
import hashlib
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class DecoySession:
    reference: str
    run: str
    expires: float
    authenticated: bool = False


class SessionStore:
    def __init__(self, *, ttl=900, capacity=512, clock=time.monotonic):
        if ttl <= 0 or capacity <= 0:
            raise ValueError("Session lifetime and capacity must be positive")
        self.ttl, self.capacity, self.clock = ttl, capacity, clock
        self._records = OrderedDict()
        self._lock = threading.RLock()

    def _prune(self):
        now = self.clock()
        for key in [k for k, value in self._records.items() if value.expires <= now]:
            del self._records[key]

    @staticmethod
    def _key(cookie):
        return hashlib.sha256(cookie.encode()).hexdigest()

    def get(self, cookie, run):
        if not cookie or len(cookie) > 128:
            return None
        with self._lock:
            self._prune()
            value = self._records.get(self._key(cookie))
            return value if value and value.run == run else None

    def create(self, run, *, authenticated=False):
        with self._lock:
            self._prune()
            while len(self._records) >= self.capacity:
                self._records.popitem(last=False)
            cookie = secrets.token_urlsafe(32)
            key = self._key(cookie)
            value = DecoySession("web_" + key, run, self.clock() + self.ttl, authenticated)
            self._records[key] = value
            return cookie, value

    def revoke(self, cookie):
        if cookie and len(cookie) <= 128:
            with self._lock:
                self._records.pop(self._key(cookie), None)
