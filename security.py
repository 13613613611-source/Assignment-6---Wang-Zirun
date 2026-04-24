"""
AI Agent Security Module
========================
Provides three composable security modules and a reusable decorator for
protecting AI pipeline agents against:
  - Prompt injection attacks
  - API abuse / quota exhaustion (rate limiting)
  - Harmful / unethical content (ethical guardrails)

Usage:
    from submit.security import with_security

    @with_security
    def process(topic: str, *, session_id=None, ip=None) -> dict:
        return call_model(topic)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any


# ----------------------------------------------------------------------
# Module-level shared instances (stateful, so one instance per process)
# ----------------------------------------------------------------------
_shared_limiter = None  # lazily initialised


def _get_limiter() -> RateLimiter:
    global _shared_limiter
    if _shared_limiter is None:
        _shared_limiter = RateLimiter(_store=_get_rate_limiter_store())
    return _shared_limiter


# ----------------------------------------------------------------------
# Prompt injection — compiled regex patterns
# ----------------------------------------------------------------------
_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\bignore\s?[,/]?\s*(instructions?)?\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(all\s+)?(your\s+)?(instructions?)?\b", re.IGNORECASE),
    re.compile(r"^\s*system\s*:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\boverride\s+(your\s+)?(system\s+)?(behavior|prompt|instructions)\b", re.IGNORECASE),
    re.compile(r"\breveal\s+(your\s+)?(system\s+)?(prompt|instructions|config)\b", re.IGNORECASE),
]

_HTML_INJECTION_PATTERN = re.compile(
    r"<(script|style|iframe|object|embed|form|input)\b[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
_NULL_BYTES_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


# ----------------------------------------------------------------------
# Ethical guard — harmful content keyword categories
# ----------------------------------------------------------------------
_HARMFUL_CATEGORIES: dict[str, list[str]] = {
    "Violence": [
        "kill", "murder", "bomb", "attack", "weapon",
        "terror", "shoot", "stab", "rape",
    ],
    "Discrimination": [
        "hate", "racist", "nazi", "supremacy",
        "slur", "discriminate", "segregate",
    ],
    "Sexual": [
        "porn", "nude", "explicit sexual",
        "underage sexual", "child sexual abuse",
    ],
    "Criminal": [
        "how to hack", "drug manufacture", "bomb make",
        "illegal weapon", "how to make毒品",
    ],
    "SelfHarm": [
        "suicide", "self-harm", "cut myself",
        "end my life", "kill myself",
    ],
}


# ----------------------------------------------------------------------
# InputValidator
# ----------------------------------------------------------------------
class InputValidator:
    """Validates and sanitizes user-supplied text before it reaches the model."""

    def __init__(self, max_length: int = 1000, max_words: int = 200) -> None:
        self.max_length = max_length
        self.max_words = max_words

    def validate(self, text: str) -> tuple[bool, str]:
        """
        Return (True, "") if the input is valid.
        Return (False, reason) if the input should be blocked.
        """
        if not text or not text.strip():
            return False, "Input cannot be empty."

        if len(text) > self.max_length:
            return False, (
                f"Input exceeds maximum length of {self.max_length} characters."
            )

        words = text.split()
        if len(words) > self.max_words:
            return False, f"Input exceeds maximum of {self.max_words} words."

        if _NULL_BYTES_PATTERN.search(text):
            return False, "Input contains disallowed control characters."

        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(text):
                return False, "Potentially malicious prompt injection detected."

        return True, ""

    def sanitize(self, text: str) -> str:
        """Remove HTML injection tags and control characters."""
        text = _HTML_INJECTION_PATTERN.sub("", text)
        text = _NULL_BYTES_PATTERN.sub("", text)
        return text.strip()


# ----------------------------------------------------------------------
# SecurityContext
# ----------------------------------------------------------------------
@dataclass
class SecurityContext:
    """
    Bundles client identity information used by all security modules.
    The identifier property prefers session_id, falls back to IP, then 'anonymous'.
    """
    session_id: str | None = None
    ip: str | None = None

    @property
    def identifier(self) -> str:
        return self.session_id or self.ip or "anonymous"


# ----------------------------------------------------------------------
# RateLimiter
# ----------------------------------------------------------------------
class RateLimiter:
    """
    Sliding-window rate limiter using in-memory timestamps.

    All instances share the same backing store (_timestamps) so that
    RateLimiter() and _get_limiter() refer to the same state.
    """

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
        _store: defaultdict[str, list[datetime]] | None = None,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Share the module-level store so all instances stay in sync
        self._timestamps: defaultdict[str, list[datetime]] = (
            _store if _store is not None else _get_rate_limiter_store()
        )

    def check(self, identifier: str) -> tuple[bool, str]:
        """
        Return (True, "") if the request is allowed.
        Return (False, message) if the rate limit has been exceeded.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        entries = self._timestamps[identifier]
        self._timestamps[identifier] = [ts for ts in entries if ts > cutoff]

        if len(self._timestamps[identifier]) >= self.max_requests:
            oldest = min(self._timestamps[identifier])
            reset_at = oldest + timedelta(seconds=self.window_seconds)
            wait = int((reset_at - now).total_seconds()) + 1
            return False, f"Rate limit exceeded. Please wait {wait} seconds."
        self._timestamps[identifier].append(now)
        return True, ""

    def get_remaining(self, identifier: str) -> int:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        active = [ts for ts in self._timestamps[identifier] if ts > cutoff]
        return max(0, self.max_requests - len(active))

    def reset(self, identifier: str) -> None:
        self._timestamps[identifier].clear()


# Module-level shared store — single source of truth for all RateLimiter instances
_rate_limiter_store: defaultdict[str, list[datetime]] = defaultdict(list)


def _get_rate_limiter_store() -> defaultdict[str, list[datetime]]:
    return _rate_limiter_store


# ----------------------------------------------------------------------
# EthicalGuard
# ----------------------------------------------------------------------
class EthicalGuard:
    """Keyword-based harmful content detector for both input and output."""

    def check_input(self, text: str) -> tuple[bool, str]:
        return self._check(text)

    def check_output(self, text: str) -> tuple[bool, str]:
        return self._check(text)

    def _check(self, text: str) -> tuple[bool, str]:
        if not text:
            return True, ""
        text_lower = text.lower()
        for category, keywords in _HARMFUL_CATEGORIES.items():
            for kw in keywords:
                if kw.lower() in text_lower:
                    return False, (
                        f"Content flagged as potentially harmful "
                        f"({category}). Please revise your request."
                    )
        return True, ""


# ----------------------------------------------------------------------
# @with_security decorator
# ----------------------------------------------------------------------
def with_security(func):
    """
    Decorator applying all three security checks before and after a
    pipeline entry point.

    Args:
        func: The function to wrap. Must accept at least a ``topic`` positional
              argument and optional ``session_id`` / ``ip`` keyword arguments.

    Returns:
        A wrapped function that returns a ``dict`` with either:
          - ``{"success": True, ...}`` on success, or
          - ``{"success": False, "error": reason, "blocked_by": module}`` on block.
    """
    @wraps(func)
    def wrapper(
        topic: str,
        *,
        session_id: str | None = None,
        ip: str | None = None,
        **kwargs: Any,
    ) -> dict:
        ctx = SecurityContext(session_id=session_id, ip=ip)

        # 1. Input validation
        validator = InputValidator()
        valid, msg = validator.validate(topic)
        if not valid:
            return {"success": False, "error": msg, "blocked_by": "input_validator"}

        # 2. Rate limit (shared module-level instance)
        limiter = _get_limiter()
        ok, msg = limiter.check(ctx.identifier)
        if not ok:
            return {"success": False, "error": msg, "blocked_by": "rate_limiter"}

        # 3. Ethical guard — input
        guard = EthicalGuard()
        safe, msg = guard.check_input(topic)
        if not safe:
            return {"success": False, "error": msg, "blocked_by": "ethical_guard"}

        # 4. Execute the wrapped function
        result = func(topic, **kwargs)

        # 5. Ethical guard — output
        safe, msg = guard.check_output(str(result))
        if not safe:
            return {
                "success": False,
                "error": msg,
                "blocked_by": "ethical_guard_output",
            }

        return result

    return wrapper
