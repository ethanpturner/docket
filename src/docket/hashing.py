"""One hash function, one format, one place.

`sha256:` followed by 64 lowercase hex characters, over bytes. Everything that gets hashed here --
a quoted span, a claim's content -- goes through `content_hash`, so a digest that appears in a
record and a digest that appears in a test were computed the same way.

Hashing takes bytes rather than `str` because the encoding is exactly what a hash of a source file
exists to pin down. A helper taking text would choose an encoding on the caller's behalf and
absorb the difference silently.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Final

__all__ = ["ALGORITHM", "content_hash", "hash_text", "is_content_hash", "verify_hash"]

ALGORITHM: Final = "sha256"

# Uppercase is rejected rather than normalised: two spellings of one digest compare unequal as
# strings, and a value sometimes normalised is worse than one always refused.
_CONTENT_HASH: Final = re.compile(rf"^{ALGORITHM}:[0-9a-f]{{64}}$")


def content_hash(data: bytes) -> str:
    """The `sha256:<hex>` digest of `data`."""
    return f"{ALGORITHM}:{hashlib.sha256(data).hexdigest()}"


def hash_text(text: str) -> str:
    """The digest of `text` encoded as UTF-8."""
    return content_hash(text.encode("utf-8"))


def is_content_hash(value: str) -> bool:
    """Whether `value` is a well-formed digest. Says nothing about what it hashes."""
    return isinstance(value, str) and _CONTENT_HASH.match(value) is not None


def verify_hash(expected: str, data: bytes) -> bool:
    """Whether `data` still hashes to `expected`."""
    if not is_content_hash(expected):
        raise ValueError(
            f"{expected!r} is not a content hash: expected {ALGORITHM!r} followed by a colon and "
            f"64 lowercase hexadecimal characters"
        )
    return hmac.compare_digest(expected, content_hash(data))
