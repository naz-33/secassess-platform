"""Sanitization and safety utilities for report text and excerpts."""
import re
from typing import Optional

# Valid XML 1.0 characters regex:
# Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
_XML_INVALID_RE = re.compile(
    r"[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]"
)

# Strip HTML tags
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def sanitize_text(text: Optional[str], max_length: Optional[int] = None) -> str:
    """
    Sanitize untrusted text to ensure safe document rendering:
    1. Replaces None with empty string.
    2. Strips XML-invalid and dangerous control characters.
    3. Normalizes newlines.
    4. Truncates cleanly if exceeding max_length with [truncated] suffix.
    """
    if text is None:
        return ""

    if not isinstance(text, str):
        text = str(text)

    # 1. Strip XML-invalid characters
    clean = _XML_INVALID_RE.sub("", text)

    # 2. Normalize carriage returns
    clean = clean.replace("\r\n", "\n").replace("\r", "\n")

    # 3. Truncate if required
    if max_length and len(clean) > max_length:
        clean = clean[:max_length].rstrip() + " [truncated]"

    return clean


def strip_html_tags(text: Optional[str]) -> str:
    """Strip HTML markup from untrusted text to prevent pseudo-markup injection."""
    if not text:
        return ""
    return _HTML_TAG_RE.sub("", text)

