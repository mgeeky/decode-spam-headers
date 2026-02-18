from __future__ import annotations

import asyncio
import math
import secrets
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque

from fastapi import status
from fastapi.responses import JSONResponse

CAPTCHA_PLACEHOLDER_IMAGE_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO6sZcQAAAAASUVORK5CYII="
)


@dataclass(frozen=True)
class CaptchaChallengePayload:
    challenge_token: str
    image_base64: str


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self._limit = max(1, int(limit))
        self._window_seconds = max(1, int(window_seconds))
        self._lock = asyncio.Lock()
        self._requests: dict[str, Deque[float]] = {}

    async def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        async with self._lock:
            bucket = self._requests.get(key)
            if bucket is None:
                bucket = deque()
                self._requests[key] = bucket

            cutoff = now - self._window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self._limit:
                retry_after = self._compute_retry_after(bucket, now)
                return False, retry_after

            bucket.append(now)
            return True, 0

    def _compute_retry_after(self, bucket: Deque[float], now: float) -> int:
        if not bucket:
            return self._window_seconds
        oldest = bucket[0]
        remaining = self._window_seconds - (now - oldest)
        return max(1, math.ceil(remaining))


class RateLimiterMiddleware:
    def __init__(
        self,
        app,
        *,
        limiter: SlidingWindowRateLimiter,
        protected_paths: set[str] | None = None,
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.protected_paths = protected_paths or set()

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.protected_paths and path not in self.protected_paths:
            await self.app(scope, receive, send)
            return

        if scope.get("method", "").upper() == "OPTIONS":
            await self.app(scope, receive, send)
            return

        client_ip = _get_client_ip(scope)
        allowed, retry_after = await self.limiter.check(client_ip)
        if allowed:
            await self.app(scope, receive, send)
            return

        challenge = _create_captcha_challenge()
        response = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Too many requests",
                "retryAfter": retry_after,
                "captchaChallenge": {
                    "challengeToken": challenge.challenge_token,
                    "imageBase64": challenge.image_base64,
                },
            },
            headers={"Retry-After": str(retry_after)},
        )
        await response(scope, receive, send)


def _create_captcha_challenge() -> CaptchaChallengePayload:
    return CaptchaChallengePayload(
        challenge_token=secrets.token_urlsafe(16),
        image_base64=CAPTCHA_PLACEHOLDER_IMAGE_BASE64,
    )


def _get_client_ip(scope) -> str:
    headers = scope.get("headers") or []
    forwarded_for = None
    for key, value in headers:
        if key.lower() == b"x-forwarded-for":
            forwarded_for = value.decode("utf-8", errors="ignore")
            break
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or "unknown"

    client = scope.get("client")
    if client and client[0]:
        return str(client[0])
    return "unknown"
