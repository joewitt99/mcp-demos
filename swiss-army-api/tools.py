"""The 25 swiss-army-api tools — a subset of swiss-army-mcp's 100.

Implementations are copied verbatim from ``swiss-army-mcp/server.py`` so the
same tool name returns the same result through either server. Each function is
registered with ``@tool`` instead of ``@mcp.tool``; ``app.py`` turns every
registered function into a REST operation whose ``operationId`` is the
function name, so an OpenAPI→MCP bridge surfaces the same tool names as
swiss-army-mcp.

Categories (prefix → tools):
  text_ 3   math_ 3   encode_ 3   hash_ 2   time_ 3
  rand_ 2   color_ 2  unit_ 2     data_ 3   fun_ 2
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import re
import secrets
import string
import urllib.parse
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Callable

TOOLS: list[Callable] = []


def tool(fn: Callable) -> Callable:
    """Register ``fn`` as a REST operation (the analogue of ``@mcp.tool``)."""
    TOOLS.append(fn)
    return fn


# ============================================================================
# 1. TEXT (3)
# ============================================================================

@tool
def text_uppercase(text: str) -> str:
    """Convert text to UPPERCASE."""
    return text.upper()


@tool
def text_word_count(text: str) -> int:
    """Count the number of whitespace-separated words in text."""
    return len(text.split())


@tool
def text_slugify(text: str) -> str:
    """Convert text into a url-friendly slug (lowercase, hyphens, ascii-only)."""
    s = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"[\s_]+", "-", s).strip("-")


# ============================================================================
# 2. MATH (3)
# ============================================================================

@tool
def math_add(a: float, b: float) -> float:
    """Return a + b."""
    return a + b


@tool
def math_divide(a: float, b: float) -> float:
    """Return a / b. Raises if b == 0."""
    if b == 0:
        raise ValueError("Division by zero")
    return a / b


@tool
def math_factorial(n: int) -> int:
    """Return n! (n must be a non-negative integer)."""
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    return math.factorial(n)


# ============================================================================
# 3. ENCODING (3)
# ============================================================================

@tool
def encode_base64(text: str) -> str:
    """Encode text to base64."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


@tool
def encode_base64_decode(data: str) -> str:
    """Decode a base64 string back to text."""
    return base64.b64decode(data.encode("ascii")).decode("utf-8")


@tool
def encode_url(text: str) -> str:
    """URL-percent-encode the given text."""
    return urllib.parse.quote(text, safe="")


# ============================================================================
# 4. HASHING (2)
# ============================================================================

@tool
def hash_sha256(text: str) -> str:
    """Return SHA-256 hex digest of text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@tool
def hash_password_strength(password: str) -> dict:
    """Score a password's strength. Returns score 0-5 and a label."""
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    labels = ["very weak", "weak", "fair", "good", "strong", "very strong"]
    return {"score": score, "label": labels[score], "length": len(password)}


# ============================================================================
# 5. DATE/TIME (3)
# ============================================================================

@tool
def time_current_iso() -> str:
    """Return the current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


@tool
def time_days_between(start_date: str, end_date: str) -> int:
    """Return the number of days between two ISO dates (YYYY-MM-DD)."""
    d1 = date.fromisoformat(start_date)
    d2 = date.fromisoformat(end_date)
    return (d2 - d1).days


@tool
def time_add_days(start_date: str, days: int) -> str:
    """Add `days` to an ISO date and return the resulting ISO date."""
    return (date.fromisoformat(start_date) + timedelta(days=days)).isoformat()


# ============================================================================
# 6. RANDOM (2)
# ============================================================================

@tool
def rand_uuid() -> str:
    """Return a freshly generated UUID4."""
    return str(uuid.uuid4())


@tool
def rand_password(length: int = 16, include_symbols: bool = True) -> str:
    """Generate a cryptographically strong random password."""
    alphabet = string.ascii_letters + string.digits
    if include_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ============================================================================
# 7. COLOR (2)
# ============================================================================

def _hex_to_rgb_tuple(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    if len(h) != 6:
        raise ValueError("hex color must be #RGB or #RRGGBB")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


@tool
def color_hex_to_rgb(hex_color: str) -> dict:
    """Convert a hex color (e.g. #FF8800) to RGB components."""
    r, g, b = _hex_to_rgb_tuple(hex_color)
    return {"r": r, "g": g, "b": b}


@tool
def color_contrast_ratio(hex_a: str, hex_b: str) -> float:
    """WCAG contrast ratio between two hex colors (1.0 - 21.0)."""
    def _lum(hex_color: str) -> float:
        r, g, b = _hex_to_rgb_tuple(hex_color)
        def chan(c: float) -> float:
            c = c / 255
            return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
        return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)
    la, lb = _lum(hex_a), _lum(hex_b)
    lighter, darker = max(la, lb), min(la, lb)
    return round((lighter + 0.05) / (darker + 0.05), 2)


# ============================================================================
# 8. UNITS (2)
# ============================================================================

@tool
def unit_celsius_to_fahrenheit(celsius: float) -> float:
    """Convert Celsius to Fahrenheit."""
    return celsius * 9 / 5 + 32


@tool
def unit_miles_to_km(miles: float) -> float:
    """Convert miles to kilometers."""
    return miles * 1.609344


# ============================================================================
# 9. DATA (3)
# ============================================================================

@tool
def data_json_validate(text: str) -> dict:
    """Check whether a string is valid JSON. Returns {valid, error?}."""
    try:
        json.loads(text)
        return {"valid": True}
    except json.JSONDecodeError as e:
        return {"valid": False, "error": str(e)}


@tool
def data_regex_match(pattern: str, text: str) -> list[str]:
    """Return all non-overlapping matches of a regex pattern in text."""
    return re.findall(pattern, text)


@tool
def data_base_convert(number: str, from_base: int = 10, to_base: int = 2) -> str:
    """Convert a number from one base (2-36) to another."""
    if not (2 <= from_base <= 36 and 2 <= to_base <= 36):
        raise ValueError("bases must be between 2 and 36")
    n = int(number, from_base)
    if n == 0:
        return "0"
    digits = string.digits + string.ascii_lowercase
    sign = "-" if n < 0 else ""
    n = abs(n)
    out = []
    while n:
        n, r = divmod(n, to_base)
        out.append(digits[r])
    return sign + "".join(reversed(out))


# ============================================================================
# 10. FUN (2)
# ============================================================================

@tool
def fun_joke() -> str:
    """Tell a (corny) programmer joke."""
    jokes = [
        "Why do programmers prefer dark mode? Because light attracts bugs.",
        "There are 10 types of people: those who understand binary and those who don't.",
        "A SQL query walks into a bar, sees two tables and asks: 'Can I join you?'",
        "Why do Java developers wear glasses? Because they don't C#.",
        "I would tell you a UDP joke, but you might not get it.",
        "How many programmers does it take to change a light bulb? None — that's a hardware problem.",
        "Real programmers count from zero.",
        "There's no place like 127.0.0.1.",
    ]
    return random.choice(jokes)


@tool
def fun_rock_paper_scissors(player: str) -> dict:
    """Play rock-paper-scissors. player is 'rock', 'paper', or 'scissors'."""
    player = player.lower().strip()
    if player not in {"rock", "paper", "scissors"}:
        raise ValueError("player must be rock, paper, or scissors")
    cpu = random.choice(["rock", "paper", "scissors"])
    if player == cpu:
        result = "tie"
    elif (player, cpu) in {("rock", "scissors"), ("paper", "rock"), ("scissors", "paper")}:
        result = "win"
    else:
        result = "lose"
    return {"player": player, "cpu": cpu, "result": result}
