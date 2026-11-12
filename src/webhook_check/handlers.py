"""Language-independent part: a detected handler, its classification, and the handler-level
rules (WHK001 no verification, WHK006 Razorpay payment trust, WHK007 no de-duplication)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .findings import Finding, redact_line
from .providers import BY_KEY, DEDUPE_RE, GENERIC_VERIFY_RE, first_event, has_write, identify

PAYMENT_ID_RE = re.compile(r"razorpay_payment_id")
PAYMENT_VERIFY_RE = re.compile(
    r"\bvalidatePaymentVerification\s*\(|\bverify_payment_signature\s*\(|\bcreateHmac\s*\(|\bhmac\s*\.\s*new\s*\(|"
    r"\bpayments?\s*\.\s*fetch\s*\(|\bfetchPayment\w*\s*\(|\bpayment\s*\.\s*fetch\s*\(|\borders?\s*\.\s*fetchPayments\s*\(|"
    r"\bsubscriptions?\s*\.\s*fetch\s*\("
)

BODY_ACCESS = {
    "js": re.compile(
        r"(?<![\w$])(?:req|request|ctx\s*\.\s*request|ctx\s*\.\s*req|c\s*\.\s*req|event)\s*\.\s*"
        r"(?:body|rawBody|json|text|arrayBuffer|formData|blob|valid|payload)\b|"
        r"\bbuffer\s*\(\s*req\b|\bgetRawBody\s*\(|\brawBody\b|for\s+await\s*\(\s*const\s+\w+\s+of\s+req\b|"
        r"@Body\s*\(|@RawBody|"
        r"\b(?:verifyWebhook|authenticate\s*\.\s*webhook|webhooks\s*\.\s*validate)\s*\("
    ),
    "py": re.compile(
        r"\brequest\s*\.\s*(?:body|data|get_data|get_json|json|form|POST|stream|text|content|values)\b"
    ),
}
# The same, for the few patterns that need string contents (checked on comment-free text).
BODY_ACCESS_STR = {
    "js": re.compile(r"\breq\s*\.\s*on\s*\(\s*['\"]data['\"]"),
    "py": re.compile(r"\bevent\s*\[\s*['\"]body['\"]\s*\]|\bevent\s*\.\s*get\(\s*['\"]body['\"]"),
}
# Reading request headers (enough when the handler also has strong provider evidence).
HEADER_ACCESS = {
    "js": re.compile(r"(?<![\w$])(?:req|request|c\s*\.\s*req|ctx\s*\.\s*(?:request|req)|event)\s*\.\s*"
                     r"(?:headers|header|get)\b|@Headers?\s*\("),
    "py": re.compile(r"\brequest\s*\.\s*(?:headers|META)\b|\bevent\s*\[\s*['\"]headers['\"]\s*\]"),
}


@dataclass
class Handler:
    file: str
    line: int                 # where the handler is declared (route / decorator / function)
    lang: str                 # "js" | "py"
    framework: str            # next-app, next-pages, express, hono, fastify, nestjs, node, fastapi, flask, django, python
    label: str                # "POST /api/webhooks/stripe" or "stripe_webhook()"
    route: str | None
    explicit: bool            # a registered route (not just a function that looks like one)
    own: str                  # handler text: comments removed, strings kept
    context: str              # own + same-file helpers + middleware/decorators (strings kept)
    context_code: str         # the same with string contents blanked
    own_start_line: int
    lines: list[str] = field(repr=False, default_factory=list)
    opaque: bool = False      # wrapped by an unknown middleware / decorator that may verify
    provider: str | None = None
    kind: str | None = None   # "webhook" | "razorpay-payment"
    verified: bool | None = None

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "handler": self.label, "framework": self.framework,
                "provider": BY_KEY[self.provider].label if self.provider else None, "kind": self.kind,
                "signature_verified": self.verified}


def classify(h: Handler, file_text: str) -> None:
    # request access must be real code (strings blanked), so regexes and docs never count
    reads_body = bool(BODY_ACCESS[h.lang].search(h.context_code) or BODY_ACCESS_STR[h.lang].search(h.context))
    if not reads_body and not HEADER_ACCESS[h.lang].search(h.context_code):
        return
    if reads_body and PAYMENT_ID_RE.search(h.context) and not re.search(r"x-razorpay-signature", h.context, re.I):
        h.kind, h.provider = "razorpay-payment", "razorpay"
        return
    p, how = identify(h.context, h.route or h.label, file_text, explicit_route=h.explicit)
    # without a body read, only provider headers / verification calls make it a webhook handler
    if p is not None and (reads_body or how == "strong"):
        h.kind, h.provider = "webhook", p.key


def handler_findings(h: Handler, secrets: list[str]) -> list[Finding]:
    out: list[Finding] = []
    extra = {"lang": h.lang, "framework": h.framework, "provider": h.provider, "route": h.route or ""}
    evidence = redact_line(h.lines[h.line - 1] if 0 < h.line <= len(h.lines) else "", secrets)
    if h.kind == "razorpay-payment":
        verified = bool(PAYMENT_VERIFY_RE.search(h.context_code) or GENERIC_VERIFY_RE.search(h.context_code))
        h.verified = True if verified else (None if h.opaque else False)
        if h.verified is False:
            m = PAYMENT_ID_RE.search(h.own)
            line = h.own_start_line + h.own[: m.start()].count("\n") if m else h.line
            ev = redact_line(h.lines[line - 1] if 0 < line <= len(h.lines) else "", secrets)
            out.append(Finding(
                "WHK006", "critical",
                f"{h.label} reads razorpay_payment_id from the client (Razorpay Checkout callback) and never "
                f"verifies razorpay_signature = HMAC-SHA256(order_id + \"|\" + payment_id, key_secret): anyone can "
                f"post a made-up or reused payment id and get the order marked paid.",
                h.file, line, ev, extra=extra))
        return out
    if h.kind != "webhook":
        return out
    p = BY_KEY[h.provider]
    verified = bool(p.verify.search(h.context_code) or p.verify.search(h.context)
                    or GENERIC_VERIFY_RE.search(h.context_code))
    h.verified = True if verified else (None if h.opaque else False)
    ev_name = first_event(h.context, p)
    if h.verified is False:
        what = f" (e.g. '{ev_name}')" if ev_name else ""
        out.append(Finding(
            "WHK001", p.severity,
            f"{h.label} handles {p.label} webhook events{what} but never verifies the signature in {p.header}: "
            f"anyone who can reach this URL can send a forged event; {p.impact}.",
            h.file, h.line, evidence, extra=extra))
    if p.key != "twilio" and has_write(h.context_code) and not DEDUPE_RE.search(h.context) and \
            not (p.dedupe and p.dedupe.search(h.context)):
        out.append(Finding(
            "WHK007", "low",
            f"{h.label} changes state for {p.label} events but never records the event id ({p.event_id}): "
            f"retries, dashboard re-sends and replays apply the same event twice.",
            h.file, h.line, evidence, heuristic=True, extra=extra))
    return out
