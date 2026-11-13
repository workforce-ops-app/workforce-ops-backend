"""Normalization: simplify a value before it is matched (docs/features/detection.md).

Attackers disguise input so that a plain search misses it: a quote sent as %27 (or %2527,
encoded twice), a tag sent as &lt;script&gt;, a full-width < that looks like the real one,
or SQL keywords split by empty comments (UNION/**/SELECT). normalize() undoes these
disguises, in the order the design gives, so one pattern catches every form.

The result is used ONLY for matching. What gets stored and shown is the original text
(detector.excerpt), so the security page shows what was really sent.

This module is plain Python: no FastAPI, no database (rule DE10), so the detection study
scores exactly the code the API runs.
"""

import html
import re
import unicodedata
from urllib.parse import unquote_plus

# MySQL runs code inside a "version comment" such as /*!50000UNION*/, so its text must be
# kept: only the opening marker is removed. Bounded to 6 digits (MySQL versions are 5).
_VERSION_COMMENT_START = re.compile(r"/\*!\d{0,6}")
# An ordinary inline comment, which attackers put where a space would go. Bounded, so a
# value full of "/*" with no end cannot make this search slow (rule DE5).
_INLINE_COMMENT = re.compile(r"/\*.{0,200}?\*/", re.DOTALL)
# Any run of whitespace (spaces, tabs, newlines, and the Unicode ones NFKC leaves).
_WHITESPACE = re.compile(r"\s+")


def normalize(value: str, *, url_decode: bool = True) -> str:
    """The value decoded and simplified for matching (steps 1 to 5 of the design).

    url_decode=False skips step 1. The detector matches every value both ways, because
    URL-decoding can also DESTROY an attack: in the printf attack %08x, "%08" reads as an
    encoded byte, so the decoded text no longer contains it.
    """
    # 1. URL-decode, at most twice: %2527 becomes %27 and then a quote. A second round only
    #    runs if the first one changed something. unquote_plus also turns "+" into a space,
    #    as a browser's form encoding does (UNION+SELECT).
    text = value
    if url_decode:
        text = unquote_plus(value)
        if text != value:
            text = unquote_plus(text)

    # 2. Decode HTML entities: &lt;script&gt; becomes <script>, &#39; becomes a quote.
    text = html.unescape(text)

    # 3. Unicode NFKC: look-alike characters become the plain ones, for example the
    #    full-width "＜" (U+FF1C) becomes "<", and "ｓｃｒｉｐｔ" becomes "script".
    text = unicodedata.normalize("NFKC", text)

    # 4. Lowercase, so patterns never need to care about UnIoN or ScRiPt.
    text = text.lower()

    # 5. SQL comments become spaces (UNION/**/SELECT reads as "union select"), keeping the
    #    text of version comments, then every run of whitespace becomes a single space.
    text = _VERSION_COMMENT_START.sub(" ", text)
    text = _INLINE_COMMENT.sub(" ", text)
    text = text.replace("*/", " ")
    return _WHITESPACE.sub(" ", text)
