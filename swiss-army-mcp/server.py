"""Swiss Army Knife MCP — exactly 100 demo tools across 10 categories.

Categories (10 tools each):
  1.  Text         2.  Math          3.  Encoding      4.  Hashing
  5.  Date/Time    6.  Random        7.  Color         8.  Units
  9.  Data         10. Fun

Run locally:    python server.py
Render/Docker:  PORT and HOST env vars are honored.
"""

from __future__ import annotations

import base64
import binascii
import colorsys
import csv
import hashlib
import hmac
import io
import json
import logging
import math
import os
import random
import re
import secrets
import string
import urllib.parse
import uuid
import zlib
from datetime import date, datetime, timedelta, timezone
from html import escape as html_escape_fn
from html import unescape as html_unescape_fn

from fastmcp import FastMCP

from config_routes import register_config_routes
from okta_auth import MultiTenantOktaVerifier
from scopes import ScopeMiddleware
from tenant_config import TenantStore

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

# MCP-spec cursor pagination for list operations (tools/resources/prompts).
# Clients send an opaque `cursor`; responses include `nextCursor` until exhausted.
LIST_PAGE_SIZE = int(os.environ.get("MCP_LIST_PAGE_SIZE", "30"))

# This is the single shared instance; each request's tenant is identified by
# the bearer token's `iss` claim and dispatched to a per-tenant verifier.
_PUBLIC_BASE_URL = os.environ.get("MCP_BASE_URL") or None
_AUTH_DISABLED = os.environ.get("MCP_AUTH_DISABLED", "").lower() == "true"
if _AUTH_DISABLED:
    logging.warning("MCP_AUTH_DISABLED=true — Okta auth is OFF. Do not use in prod.")

_store: TenantStore | None = None if _AUTH_DISABLED else TenantStore()
_workload_verifier: MultiTenantOktaVerifier | None = (
    None if _store is None
    else MultiTenantOktaVerifier(store=_store, base_url=_PUBLIC_BASE_URL)
)

_middleware = [ScopeMiddleware(_store)] if _store is not None else []

mcp = FastMCP(
    name="swiss-army-mcp",
    instructions=(
        "A 100-tool Swiss Army Knife demo MCP server. Tools are namespaced with a "
        "category prefix: text_, math_, encode_, hash_, time_, rand_, color_, "
        "unit_, data_, fun_. tools/list is paginated; follow nextCursor to "
        "retrieve all 100 tools."
    ),
    auth=_workload_verifier,
    middleware=_middleware,
    list_page_size=LIST_PAGE_SIZE,
)


# ============================================================================
# 1. TEXT (10)
# ============================================================================

@mcp.tool
def text_uppercase(text: str) -> str:
    """Convert text to UPPERCASE."""
    return text.upper()


@mcp.tool
def text_lowercase(text: str) -> str:
    """Convert text to lowercase."""
    return text.lower()


@mcp.tool
def text_reverse(text: str) -> str:
    """Reverse the order of characters in text."""
    return text[::-1]


@mcp.tool
def text_word_count(text: str) -> int:
    """Count the number of whitespace-separated words in text."""
    return len(text.split())


@mcp.tool
def text_char_count(text: str, include_whitespace: bool = True) -> int:
    """Count characters. Set include_whitespace=False to ignore spaces/tabs/newlines."""
    if include_whitespace:
        return len(text)
    return sum(1 for c in text if not c.isspace())


@mcp.tool
def text_title_case(text: str) -> str:
    """Convert text To Title Case."""
    return text.title()


@mcp.tool
def text_snake_case(text: str) -> str:
    """Convert text to snake_case."""
    s = re.sub(r"(?<!^)(?=[A-Z])", "_", text).lower()
    s = re.sub(r"[\s\-]+", "_", s)
    return re.sub(r"_+", "_", s).strip("_")


@mcp.tool
def text_camel_case(text: str) -> str:
    """Convert text to camelCase."""
    parts = re.split(r"[\s_\-]+", text.strip())
    if not parts:
        return ""
    return parts[0].lower() + "".join(p.capitalize() for p in parts[1:])


@mcp.tool
def text_slugify(text: str) -> str:
    """Convert text into a url-friendly slug (lowercase, hyphens, ascii-only)."""
    s = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"[\s_]+", "-", s).strip("-")


@mcp.tool
def text_truncate(text: str, max_length: int = 80, suffix: str = "...") -> str:
    """Truncate text to max_length characters, adding suffix if shortened."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


# ============================================================================
# 2. MATH (10)
# ============================================================================

@mcp.tool
def math_add(a: float, b: float) -> float:
    """Return a + b."""
    return a + b


@mcp.tool
def math_subtract(a: float, b: float) -> float:
    """Return a - b."""
    return a - b


@mcp.tool
def math_multiply(a: float, b: float) -> float:
    """Return a * b."""
    return a * b


@mcp.tool
def math_divide(a: float, b: float) -> float:
    """Return a / b. Raises if b == 0."""
    if b == 0:
        raise ValueError("Division by zero")
    return a / b


@mcp.tool
def math_power(base: float, exponent: float) -> float:
    """Return base raised to exponent."""
    return math.pow(base, exponent)


@mcp.tool
def math_sqrt(value: float) -> float:
    """Return the square root of value (value must be >= 0)."""
    if value < 0:
        raise ValueError("Cannot take sqrt of negative number")
    return math.sqrt(value)


@mcp.tool
def math_factorial(n: int) -> int:
    """Return n! (n must be a non-negative integer)."""
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    return math.factorial(n)


@mcp.tool
def math_gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of a and b."""
    return math.gcd(a, b)


@mcp.tool
def math_lcm(a: int, b: int) -> int:
    """Return the least common multiple of a and b."""
    return math.lcm(a, b)


@mcp.tool
def math_modulo(a: int, b: int) -> int:
    """Return a mod b."""
    if b == 0:
        raise ValueError("Modulo by zero")
    return a % b


# ============================================================================
# 3. ENCODING (10)
# ============================================================================

@mcp.tool
def encode_base64(text: str) -> str:
    """Encode text to base64."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


@mcp.tool
def encode_base64_decode(data: str) -> str:
    """Decode a base64 string back to text."""
    return base64.b64decode(data.encode("ascii")).decode("utf-8")


@mcp.tool
def encode_url(text: str) -> str:
    """URL-percent-encode the given text."""
    return urllib.parse.quote(text, safe="")


@mcp.tool
def encode_url_decode(text: str) -> str:
    """Decode a URL-percent-encoded string."""
    return urllib.parse.unquote(text)


@mcp.tool
def encode_hex(text: str) -> str:
    """Encode text to hexadecimal."""
    return text.encode("utf-8").hex()


@mcp.tool
def encode_hex_decode(hex_string: str) -> str:
    """Decode a hexadecimal string back to text."""
    return bytes.fromhex(hex_string).decode("utf-8")


@mcp.tool
def encode_html(text: str) -> str:
    """HTML-escape special characters in text (e.g. < becomes &lt;)."""
    return html_escape_fn(text, quote=True)


@mcp.tool
def encode_html_decode(text: str) -> str:
    """Unescape HTML entities back to characters."""
    return html_unescape_fn(text)


@mcp.tool
def encode_rot13(text: str) -> str:
    """Apply the ROT13 cipher to text."""
    table = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    return text.translate(table)


@mcp.tool
def encode_binary(text: str) -> str:
    """Encode text as a space-separated string of 8-bit binary bytes."""
    return " ".join(f"{b:08b}" for b in text.encode("utf-8"))


# ============================================================================
# 4. HASHING (10)
# ============================================================================

@mcp.tool
def hash_md5(text: str) -> str:
    """Return MD5 hex digest of text."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


@mcp.tool
def hash_sha1(text: str) -> str:
    """Return SHA-1 hex digest of text."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


@mcp.tool
def hash_sha256(text: str) -> str:
    """Return SHA-256 hex digest of text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@mcp.tool
def hash_sha512(text: str) -> str:
    """Return SHA-512 hex digest of text."""
    return hashlib.sha512(text.encode("utf-8")).hexdigest()


@mcp.tool
def hash_sha3_256(text: str) -> str:
    """Return SHA3-256 hex digest of text."""
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


@mcp.tool
def hash_blake2b(text: str) -> str:
    """Return BLAKE2b hex digest of text."""
    return hashlib.blake2b(text.encode("utf-8")).hexdigest()


@mcp.tool
def hash_crc32(text: str) -> str:
    """Return CRC32 checksum of text as 8-character hex string."""
    return f"{zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF:08x}"


@mcp.tool
def hash_hmac_sha256(text: str, key: str) -> str:
    """Return HMAC-SHA256 of text using the given key."""
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


@mcp.tool
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


@mcp.tool
def hash_fingerprint(text: str) -> str:
    """Short 16-char fingerprint of text (first 16 hex of SHA-256)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ============================================================================
# 5. DATE/TIME (10)
# ============================================================================

@mcp.tool
def time_current_iso() -> str:
    """Return the current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


@mcp.tool
def time_current_date() -> str:
    """Return today's date as YYYY-MM-DD (UTC)."""
    return datetime.now(timezone.utc).date().isoformat()


@mcp.tool
def time_days_between(start_date: str, end_date: str) -> int:
    """Return the number of days between two ISO dates (YYYY-MM-DD)."""
    d1 = date.fromisoformat(start_date)
    d2 = date.fromisoformat(end_date)
    return (d2 - d1).days


@mcp.tool
def time_add_days(start_date: str, days: int) -> str:
    """Add `days` to an ISO date and return the resulting ISO date."""
    return (date.fromisoformat(start_date) + timedelta(days=days)).isoformat()


@mcp.tool
def time_format_date(iso_date: str, fmt: str = "%B %d, %Y") -> str:
    """Format an ISO date string using a strftime pattern."""
    return date.fromisoformat(iso_date).strftime(fmt)


@mcp.tool
def time_parse_date(text: str, fmt: str = "%Y-%m-%d") -> str:
    """Parse a date string with given strftime format, return ISO date."""
    return datetime.strptime(text, fmt).date().isoformat()


@mcp.tool
def time_day_of_week(iso_date: str) -> str:
    """Return the weekday name for a given ISO date."""
    return date.fromisoformat(iso_date).strftime("%A")


@mcp.tool
def time_week_number(iso_date: str) -> int:
    """Return the ISO week number (1-53) for a given ISO date."""
    return date.fromisoformat(iso_date).isocalendar().week


@mcp.tool
def time_unix_timestamp(iso_datetime: str | None = None) -> int:
    """Return Unix epoch seconds. If iso_datetime is omitted, returns current time."""
    if iso_datetime is None:
        return int(datetime.now(timezone.utc).timestamp())
    return int(datetime.fromisoformat(iso_datetime).timestamp())


@mcp.tool
def time_age_from_birthdate(birthdate: str) -> int:
    """Compute age in whole years given an ISO birthdate (YYYY-MM-DD)."""
    born = date.fromisoformat(birthdate)
    today = date.today()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


# ============================================================================
# 6. RANDOM (10)
# ============================================================================

@mcp.tool
def rand_int(low: int = 0, high: int = 100) -> int:
    """Return a random integer N such that low <= N <= high."""
    return random.randint(low, high)


@mcp.tool
def rand_float(low: float = 0.0, high: float = 1.0) -> float:
    """Return a random float in [low, high)."""
    return random.uniform(low, high)


@mcp.tool
def rand_choice(options: list[str]) -> str:
    """Pick one element at random from the options list."""
    if not options:
        raise ValueError("options must be non-empty")
    return random.choice(options)


@mcp.tool
def rand_uuid() -> str:
    """Return a freshly generated UUID4."""
    return str(uuid.uuid4())


@mcp.tool
def rand_password(length: int = 16, include_symbols: bool = True) -> str:
    """Generate a cryptographically strong random password."""
    alphabet = string.ascii_letters + string.digits
    if include_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


@mcp.tool
def rand_hex_color() -> str:
    """Return a random hex color like #A1B2C3."""
    return "#{:06X}".format(random.randint(0, 0xFFFFFF))


@mcp.tool
def rand_dice(sides: int = 6, count: int = 1) -> list[int]:
    """Roll `count` dice each with `sides` sides."""
    return [random.randint(1, sides) for _ in range(count)]


@mcp.tool
def rand_coin_flip() -> str:
    """Flip a coin. Returns 'heads' or 'tails'."""
    return random.choice(["heads", "tails"])


@mcp.tool
def rand_lottery(pool: int = 49, picks: int = 6) -> list[int]:
    """Draw `picks` unique numbers from 1..pool."""
    if picks > pool:
        raise ValueError("picks cannot exceed pool")
    return sorted(random.sample(range(1, pool + 1), picks))


@mcp.tool
def rand_magic_8_ball(question: str = "") -> str:
    """Ask the Magic 8 Ball a yes/no question."""
    answers = [
        "It is certain.", "Without a doubt.", "Yes, definitely.",
        "You may rely on it.", "As I see it, yes.", "Most likely.",
        "Outlook good.", "Yes.", "Signs point to yes.",
        "Reply hazy, try again.", "Ask again later.",
        "Better not tell you now.", "Cannot predict now.",
        "Don't count on it.", "My reply is no.",
        "My sources say no.", "Outlook not so good.", "Very doubtful.",
    ]
    return random.choice(answers)


# ============================================================================
# 7. COLOR (10)
# ============================================================================

def _hex_to_rgb_tuple(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    if len(h) != 6:
        raise ValueError("hex color must be #RGB or #RRGGBB")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _rgb_to_hex_str(r: int, g: int, b: int) -> str:
    return "#{:02X}{:02X}{:02X}".format(
        max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b))
    )


@mcp.tool
def color_hex_to_rgb(hex_color: str) -> dict:
    """Convert a hex color (e.g. #FF8800) to RGB components."""
    r, g, b = _hex_to_rgb_tuple(hex_color)
    return {"r": r, "g": g, "b": b}


@mcp.tool
def color_rgb_to_hex(r: int, g: int, b: int) -> str:
    """Convert RGB (0-255) to a #RRGGBB hex color string."""
    return _rgb_to_hex_str(r, g, b)


@mcp.tool
def color_hex_to_hsl(hex_color: str) -> dict:
    """Convert a hex color to HSL (hue 0-360, sat/lum 0-100)."""
    r, g, b = _hex_to_rgb_tuple(hex_color)
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    return {"h": round(h * 360, 1), "s": round(s * 100, 1), "l": round(l * 100, 1)}


@mcp.tool
def color_complementary(hex_color: str) -> str:
    """Return the complementary hex color (opposite on the color wheel)."""
    r, g, b = _hex_to_rgb_tuple(hex_color)
    return _rgb_to_hex_str(255 - r, 255 - g, 255 - b)


@mcp.tool
def color_lighten(hex_color: str, percent: float = 10.0) -> str:
    """Lighten a hex color by the given percent (0-100)."""
    r, g, b = _hex_to_rgb_tuple(hex_color)
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    l = min(1.0, l + percent / 100)
    nr, ng, nb = (int(round(c * 255)) for c in colorsys.hls_to_rgb(h, l, s))
    return _rgb_to_hex_str(nr, ng, nb)


@mcp.tool
def color_darken(hex_color: str, percent: float = 10.0) -> str:
    """Darken a hex color by the given percent (0-100)."""
    r, g, b = _hex_to_rgb_tuple(hex_color)
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    l = max(0.0, l - percent / 100)
    nr, ng, nb = (int(round(c * 255)) for c in colorsys.hls_to_rgb(h, l, s))
    return _rgb_to_hex_str(nr, ng, nb)


@mcp.tool
def color_blend(hex_a: str, hex_b: str, weight: float = 0.5) -> str:
    """Blend two hex colors. weight=0 returns hex_a, weight=1 returns hex_b."""
    ra, ga, ba = _hex_to_rgb_tuple(hex_a)
    rb, gb, bb = _hex_to_rgb_tuple(hex_b)
    w = max(0.0, min(1.0, weight))
    return _rgb_to_hex_str(
        int(round(ra * (1 - w) + rb * w)),
        int(round(ga * (1 - w) + gb * w)),
        int(round(ba * (1 - w) + bb * w)),
    )


@mcp.tool
def color_distance(hex_a: str, hex_b: str) -> float:
    """Euclidean RGB distance between two hex colors (0 = identical)."""
    ra, ga, ba = _hex_to_rgb_tuple(hex_a)
    rb, gb, bb = _hex_to_rgb_tuple(hex_b)
    return round(math.sqrt((ra - rb) ** 2 + (ga - gb) ** 2 + (ba - bb) ** 2), 3)


@mcp.tool
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


@mcp.tool
def color_named(name: str) -> str:
    """Look up a CSS named color by name and return its hex value."""
    named = {
        "red": "#FF0000", "green": "#008000", "blue": "#0000FF",
        "yellow": "#FFFF00", "orange": "#FFA500", "purple": "#800080",
        "pink": "#FFC0CB", "brown": "#A52A2A", "black": "#000000",
        "white": "#FFFFFF", "gray": "#808080", "cyan": "#00FFFF",
        "magenta": "#FF00FF", "lime": "#00FF00", "navy": "#000080",
        "teal": "#008080", "olive": "#808000", "maroon": "#800000",
        "silver": "#C0C0C0", "gold": "#FFD700",
    }
    key = name.lower().strip()
    if key not in named:
        raise ValueError(f"Unknown color name: {name}")
    return named[key]


# ============================================================================
# 8. UNITS (10)
# ============================================================================

@mcp.tool
def unit_celsius_to_fahrenheit(celsius: float) -> float:
    """Convert Celsius to Fahrenheit."""
    return celsius * 9 / 5 + 32


@mcp.tool
def unit_fahrenheit_to_celsius(fahrenheit: float) -> float:
    """Convert Fahrenheit to Celsius."""
    return (fahrenheit - 32) * 5 / 9


@mcp.tool
def unit_miles_to_km(miles: float) -> float:
    """Convert miles to kilometers."""
    return miles * 1.609344


@mcp.tool
def unit_km_to_miles(km: float) -> float:
    """Convert kilometers to miles."""
    return km / 1.609344


@mcp.tool
def unit_kg_to_lbs(kg: float) -> float:
    """Convert kilograms to pounds."""
    return kg * 2.2046226218


@mcp.tool
def unit_lbs_to_kg(lbs: float) -> float:
    """Convert pounds to kilograms."""
    return lbs / 2.2046226218


@mcp.tool
def unit_feet_to_meters(feet: float) -> float:
    """Convert feet to meters."""
    return feet * 0.3048


@mcp.tool
def unit_meters_to_feet(meters: float) -> float:
    """Convert meters to feet."""
    return meters / 0.3048


@mcp.tool
def unit_gallons_to_liters(gallons: float) -> float:
    """Convert US gallons to liters."""
    return gallons * 3.785411784


@mcp.tool
def unit_liters_to_gallons(liters: float) -> float:
    """Convert liters to US gallons."""
    return liters / 3.785411784


# ============================================================================
# 9. DATA (10)
# ============================================================================

@mcp.tool
def data_json_validate(text: str) -> dict:
    """Check whether a string is valid JSON. Returns {valid, error?}."""
    try:
        json.loads(text)
        return {"valid": True}
    except json.JSONDecodeError as e:
        return {"valid": False, "error": str(e)}


@mcp.tool
def data_json_pretty(text: str, indent: int = 2) -> str:
    """Pretty-print a JSON string with the given indentation."""
    return json.dumps(json.loads(text), indent=indent, sort_keys=False)


@mcp.tool
def data_json_minify(text: str) -> str:
    """Minify a JSON string (remove all whitespace)."""
    return json.dumps(json.loads(text), separators=(",", ":"))


@mcp.tool
def data_json_keys(text: str) -> list[str]:
    """List the top-level keys of a JSON object."""
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("JSON root must be an object")
    return list(obj.keys())


@mcp.tool
def data_csv_to_json(csv_text: str, has_header: bool = True) -> str:
    """Convert CSV text to a JSON array of objects (or arrays if no header)."""
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    if not rows:
        return "[]"
    if has_header:
        header, *body = rows
        records = [dict(zip(header, row)) for row in body]
    else:
        records = rows
    return json.dumps(records, indent=2)


@mcp.tool
def data_json_to_csv(json_text: str) -> str:
    """Convert a JSON array of objects to CSV text."""
    rows = json.loads(json_text)
    if not isinstance(rows, list) or not rows:
        return ""
    headers = sorted({k for row in rows for k in (row if isinstance(row, dict) else {})})
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=headers)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in headers})
    return out.getvalue()


@mcp.tool
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


@mcp.tool
def data_regex_match(pattern: str, text: str) -> list[str]:
    """Return all non-overlapping matches of a regex pattern in text."""
    return re.findall(pattern, text)


@mcp.tool
def data_regex_replace(pattern: str, replacement: str, text: str) -> str:
    """Replace all regex matches in text with replacement."""
    return re.sub(pattern, replacement, text)


@mcp.tool
def data_json_diff(a: str, b: str) -> dict:
    """Compare two JSON objects. Returns added/removed/changed top-level keys."""
    oa, ob = json.loads(a), json.loads(b)
    if not (isinstance(oa, dict) and isinstance(ob, dict)):
        raise ValueError("both inputs must be JSON objects")
    ka, kb = set(oa), set(ob)
    return {
        "added": sorted(kb - ka),
        "removed": sorted(ka - kb),
        "changed": sorted(k for k in (ka & kb) if oa[k] != ob[k]),
    }


# ============================================================================
# 10. FUN (10)
# ============================================================================

@mcp.tool
def fun_fortune_cookie() -> str:
    """Crack open a fortune cookie."""
    fortunes = [
        "A beautiful, smart, and loving person will be coming into your life.",
        "A dubious friend may be an enemy in camouflage.",
        "A faithful friend is a strong defense.",
        "An exciting opportunity lies ahead of you.",
        "Today is a good day to try something new.",
        "The fortune you seek is in another cookie.",
        "You will be hungry again in one hour.",
        "Hidden in a valley beside an open stream — you will find your future.",
        "He who laughs at himself never runs out of things to laugh at.",
        "If you have something good in your life, don't let it go!",
    ]
    return random.choice(fortunes)


@mcp.tool
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


@mcp.tool
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


@mcp.tool
def fun_palindrome_check(text: str) -> bool:
    """Check whether text is a palindrome (ignoring case and non-alphanumerics)."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", text).lower()
    return bool(cleaned) and cleaned == cleaned[::-1]


@mcp.tool
def fun_anagram_check(a: str, b: str) -> bool:
    """Check whether two strings are anagrams (case- and space-insensitive)."""
    norm = lambda s: sorted(s.lower().replace(" ", ""))
    return norm(a) == norm(b)


@mcp.tool
def fun_word_scramble(word: str) -> str:
    """Randomly scramble the letters of a word."""
    chars = list(word)
    random.shuffle(chars)
    return "".join(chars)


@mcp.tool
def fun_leet_speak(text: str) -> str:
    """Convert text into l33t sp34k."""
    table = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7",
                            "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7"})
    return text.translate(table)


@mcp.tool
def fun_pig_latin(text: str) -> str:
    """Translate text to Pig Latin."""
    vowels = "aeiouAEIOU"
    def convert(word: str) -> str:
        if not word or not word[0].isalpha():
            return word
        if word[0] in vowels:
            return word + "way"
        for i, c in enumerate(word):
            if c in vowels:
                return word[i:] + word[:i] + "ay"
        return word + "ay"
    return " ".join(convert(w) for w in text.split())


@mcp.tool
def fun_reverse_words(text: str) -> str:
    """Reverse the order of words in text."""
    return " ".join(text.split()[::-1])


@mcp.tool
def fun_emoji_clock(iso_time: str | None = None) -> str:
    """Return the clock emoji closest to the given time (defaults to now)."""
    if iso_time:
        t = datetime.fromisoformat(iso_time)
    else:
        t = datetime.now()
    clocks = ["🕛", "🕐", "🕑", "🕒", "🕓", "🕔",
              "🕕", "🕖", "🕗", "🕘", "🕙", "🕚"]
    hour = t.hour % 12
    half = "🕧🕜🕝🕞🕟🕠🕡🕢🕣🕤🕥🕦"
    if t.minute >= 45:
        hour = (hour + 1) % 12
        return clocks[hour]
    if t.minute >= 15:
        return half[hour]
    return clocks[hour]


# ============================================================================
# Entrypoint
# ============================================================================

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))

    if not _AUTH_DISABLED:
        # Load every tenant under MCP_TENANTS_PREFIX from SSM so workload
        # tokens can be dispatched right away. New tenants register through
        # /config and live in the same caches without a restart.
        assert _store is not None and _workload_verifier is not None
        _store.hydrate()
        if not _store.all():
            logging.warning(
                "No tenants found in SSM. Workload traffic will be rejected "
                "until at least one tenant completes setup at /config."
            )
        register_config_routes(
            mcp,
            store=_store,
            workload_verifier=_workload_verifier,
            public_base_url=_PUBLIC_BASE_URL,
        )

    # Stateful HTTP (default): server issues an Mcp-Session-Id on initialize
    # and returns 404 for requests carrying an unknown session ID, per the
    # MCP Streamable HTTP spec. Useful for exercising client-side recovery.
    mcp.run(transport="http", host=host, port=port)
