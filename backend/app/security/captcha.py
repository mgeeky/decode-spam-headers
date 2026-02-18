from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import random
import secrets
import struct
import threading
import time
import zlib
from dataclasses import dataclass

from app.core.config import get_settings

BYPASS_TOKEN_HEADER = "x-captcha-bypass-token"

DIGIT_FONT: dict[str, list[str]] = {
    "0": ["111", "101", "101", "101", "111"],
    "1": ["010", "110", "010", "010", "111"],
    "2": ["111", "001", "111", "100", "111"],
    "3": ["111", "001", "111", "001", "111"],
    "4": ["101", "101", "111", "001", "001"],
    "5": ["111", "100", "111", "001", "111"],
    "6": ["111", "100", "111", "101", "111"],
    "7": ["111", "001", "010", "100", "100"],
    "8": ["111", "101", "111", "101", "111"],
    "9": ["111", "101", "111", "001", "111"],
}


@dataclass(frozen=True)
class CaptchaChallenge:
    challenge_token: str
    image_base64: str
    answer: str


@dataclass
class _ChallengeRecord:
    answer: str
    expires_at: float


_CHALLENGE_LOCK = threading.Lock()
_CHALLENGES: dict[str, _ChallengeRecord] = {}


def create_captcha_challenge() -> CaptchaChallenge:
    settings = get_settings()
    answer = _generate_answer()
    image_base64 = _render_captcha_image(answer)
    challenge_token = secrets.token_urlsafe(16)
    expires_at = time.time() + settings.captcha_challenge_ttl_seconds

    with _CHALLENGE_LOCK:
        _prune_challenges_locked()
        _CHALLENGES[challenge_token] = _ChallengeRecord(
            answer=answer, expires_at=expires_at
        )

    return CaptchaChallenge(
        challenge_token=challenge_token,
        image_base64=image_base64,
        answer=answer,
    )


def verify_captcha_answer(challenge_token: str, answer: str) -> bool:
    if not challenge_token or not answer:
        return False

    now = time.time()
    normalized = answer.strip().upper()

    with _CHALLENGE_LOCK:
        record = _CHALLENGES.get(challenge_token)
        if record is None:
            return False
        if record.expires_at <= now:
            _CHALLENGES.pop(challenge_token, None)
            return False
        if record.answer != normalized:
            return False
        _CHALLENGES.pop(challenge_token, None)
        return True


def issue_bypass_token(client_ip: str) -> str:
    settings = get_settings()
    expires_at = int(time.time() + settings.captcha_bypass_ttl_seconds)
    payload = {
        "ip": client_ip,
        "exp": expires_at,
        "nonce": secrets.token_urlsafe(8),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    payload_b64 = _b64encode(payload_json)
    signature = hmac.new(
        settings.captcha_secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    signature_b64 = _b64encode(signature)
    return f"{payload_b64}.{signature_b64}"


def verify_bypass_token(token: str, client_ip: str) -> bool:
    if not token:
        return False
    parts = token.split(".")
    if len(parts) != 2:
        return False
    payload_b64, signature_b64 = parts
    settings = get_settings()
    expected_signature = hmac.new(
        settings.captcha_secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_b64encode(expected_signature), signature_b64):
        return False
    try:
        payload_raw = _b64decode(payload_b64)
        payload = json.loads(payload_raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return False
    if payload.get("ip") != client_ip:
        return False
    expires_at = payload.get("exp")
    if not isinstance(expires_at, int):
        return False
    if expires_at < int(time.time()):
        return False
    return True


def _generate_answer(length: int = 5) -> str:
    digits = "23456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def _render_captcha_image(text: str) -> str:
    scale = 4
    padding = 6
    spacing = 4
    width = padding * 2 + len(text) * 3 * scale + (len(text) - 1) * spacing
    height = padding * 2 + 5 * scale

    pixels = bytearray(width * height * 4)
    for y in range(height):
        for x in range(width):
            noise = random.randint(0, 30)
            value = 255 - noise
            idx = (y * width + x) * 4
            pixels[idx : idx + 4] = bytes((value, value, value, 255))

    x_cursor = padding
    for ch in text:
        pattern = DIGIT_FONT.get(ch)
        if pattern is None:
            x_cursor += 3 * scale + spacing
            continue
        x_offset = x_cursor + random.randint(-1, 1)
        y_offset = padding + random.randint(-2, 2)
        for row, line in enumerate(pattern):
            for col, bit in enumerate(line):
                if bit != "1":
                    continue
                for sy in range(scale):
                    for sx in range(scale):
                        px = x_offset + col * scale + sx
                        py = y_offset + row * scale + sy
                        if 0 <= px < width and 0 <= py < height:
                            idx = (py * width + px) * 4
                            pixels[idx : idx + 4] = bytes((30, 30, 30, 255))
        x_cursor += 3 * scale + spacing

    pixels = _warp_pixels(pixels, width, height)

    for _ in range(int(width * height * 0.02)):
        px = random.randint(0, width - 1)
        py = random.randint(0, height - 1)
        idx = (py * width + px) * 4
        pixels[idx : idx + 4] = bytes((80, 80, 80, 255))

    png_bytes = _encode_png(width, height, bytes(pixels))
    return base64.b64encode(png_bytes).decode("ascii")


def _warp_pixels(pixels: bytearray, width: int, height: int) -> bytearray:
    amplitude = 2.0
    frequency = 3.0
    phase = random.random() * math.tau
    warped = bytearray(len(pixels))
    for y in range(height):
        shift = int(round(amplitude * math.sin(y / frequency + phase)))
        for x in range(width):
            src_x = x - shift
            dst_idx = (y * width + x) * 4
            if src_x < 0 or src_x >= width:
                warped[dst_idx : dst_idx + 4] = b"\xff\xff\xff\xff"
            else:
                src_idx = (y * width + src_x) * 4
                warped[dst_idx : dst_idx + 4] = pixels[src_idx : src_idx + 4]
    return warped


def _encode_png(width: int, height: int, rgba: bytes) -> bytes:
    row_bytes = width * 4
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        start = y * row_bytes
        raw.extend(rgba[start : start + row_bytes])
    compressed = zlib.compress(bytes(raw), level=6)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", compressed)
        + _png_chunk(b"IEND", b"")
    )


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return length + chunk_type + data + struct.pack(">I", crc)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _prune_challenges_locked() -> None:
    now = time.time()
    expired = [
        token for token, record in _CHALLENGES.items() if record.expires_at <= now
    ]
    for token in expired:
        _CHALLENGES.pop(token, None)
