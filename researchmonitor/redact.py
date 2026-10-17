"""Remove credentials from text before it leaves the machine (emails, push messages)."""
from __future__ import annotations

import re

MASK = "[REDACTED]"

_PATTERNS = [
    # private key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), MASK),
    # well-known token formats
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}"), MASK),          # OpenAI / Anthropic style
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), MASK),                     # GitHub
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), MASK),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}"), MASK),                            # Hugging Face
    (re.compile(r"\bre_[A-Za-z0-9_]{16,}"), MASK),                           # Resend
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), MASK),                  # Slack
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), MASK),                    # AWS access key id
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), MASK),                        # Google API key
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), MASK),  # JWT
    # Authorization headers
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[^\s'\"]+"), r"\1" + MASK),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-+/=]{12,}"), r"\1" + MASK),
    # credentials in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+(@)"), r"\1" + MASK + r"\2"),
    # key=value / key: value / --key value for secret-looking names
    (re.compile(r"(?i)(\b[\w.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
                r"private[_\-]?key|credential|sendkey)[\w.\-]*\b\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"),
     r"\1" + MASK),
    (re.compile(r"(?i)(--?[\w\-]*(?:password|passwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|sendkey)"
                r"[\w\-]*\s+)([^\s\-][^\s]*)"), r"\1" + MASK),
]


def redact(text: str | None) -> str:
    if not text:
        return text or ""
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact_argv(argv: list[str]) -> list[str]:
    out, mask_next = [], False
    secretish = re.compile(r"(?i)(password|passwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|sendkey)")
    for a in argv:
        if mask_next:
            out.append(MASK)
            mask_next = False
            continue
        if a.startswith("-") and "=" not in a and secretish.search(a):
            out.append(a)
            mask_next = True
            continue
        out.append(redact(a))
    return out
