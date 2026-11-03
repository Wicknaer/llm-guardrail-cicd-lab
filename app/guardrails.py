"""
Guardrails for the SecureBank Assistant: input & output filtering.
Each control maps to an attack class covered by the promptfoo suite.
NOTE: regex-based filters are a first layer, not a complete defense.
"""
import html
import logging
import re
import unicodedata

log = logging.getLogger("guardrails")

REFUSAL = "Sorry, I can't help with that request."
MAX_INPUT_CHARS = 2000

# ---------------------------------------------------------------------------
# INPUT GUARD - direct & indirect prompt injection
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    # "ignore all previous instructions", "disregard the above rules" ...
    r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b",
    # "system prompt", "hidden instructions" ...
    r"\b(system|hidden|initial)\s+(prompt|instructions?)\b",
    # role / mode switching
    r"\b(debug|developer|admin|god)\s+mode\b",
    r"\byou\s+are\s+now\b",
    # "repeat all the text above"
    r"\brepeat\b.{0,40}\b(text|everything|words)\b.{0,20}\babove\b",
    # direct requests for internal data
    r"\b(print|reveal|show|output|dump)\b.{0,40}\b(internal data|canary|discount code|configuration)\b",
    # instructions embedded in content (indirect injection)
    r"\[\s*system[^\]]*\]",
    r"\bnote\s+to\s+(the\s+)?(ai|assistant|llm|model)\b",
    r"<!--.*?-->",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS]

# zero-width characters often used to split keywords and evade filters
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"))


def normalize(text: str) -> str:
    """Canonicalize text before matching (NFKC, strip zero-width chars, collapse whitespace)."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", text)


def check_input(user_message: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    if len(user_message) > MAX_INPUT_CHARS:
        return False, "input-too-long"
    text = normalize(user_message)
    for i, rx in enumerate(_INJECTION_RE):
        if rx.search(text):
            return False, f"prompt-injection#{i}"
    return True, "ok"


# ---------------------------------------------------------------------------
# OUTPUT GUARD - secret / system prompt leakage, PII, unsafe HTML
# ---------------------------------------------------------------------------
SECRETS = ["CANARY-7F3A-LAB", "SB-STAFF-2026"]

# generic IBAN (e.g. TR33 0006 1005 1978 6457 8413 26) and TR mobile numbers
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:\+90|\b0)\s?5\d{2}\s?\d{3}\s?\d{2}\s?\d{2}\b")


def _ngrams(text: str, n: int = 6) -> set:
    words = re.findall(r"[^\W\d_]+", text.lower())  # letters only: data values are handled by the PII layer
    return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}


def check_output(reply: str, system_prompt: str) -> tuple[str, str]:
    """Return (safe_reply, reason)."""
    text = normalize(reply)

    # 1) known secrets / canary tokens -> block the whole answer
    for secret in SECRETS:
        if secret.lower() in text.lower():
            return REFUSAL, "secret-leak"

    # 2) verbatim system prompt leakage (any 6 consecutive words) -> block
    if _ngrams(text) & _ngrams(system_prompt):
        return REFUSAL, "system-prompt-leak"

    # 3) PII redaction (keep the answer, mask the data)
    actions = []
    safe, n = IBAN_RE.subn("[REDACTED-IBAN]", reply)
    if n:
        actions.append("redacted-iban")
    safe, n = PHONE_RE.subn("[REDACTED-PHONE]", safe)
    if n:
        actions.append("redacted-phone")

    # 4) output encoding: model output must never be rendered as HTML
    if "<" in safe or ">" in safe:
        actions.append("html-encoded")
    safe = html.escape(safe, quote=False)
    return safe, ",".join(actions) or "ok"
