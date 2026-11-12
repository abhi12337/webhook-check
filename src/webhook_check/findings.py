"""Finding model and the rule catalogue (ids, severities, why it matters, how to fix)."""

from __future__ import annotations

import re
import textwrap
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}  # lower = worse


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str     # default / range shown by `webhook-check rules`
    why: str
    fix: str          # generic fix; findings carry a provider- and framework-specific one


RULES: dict[str, Rule] = {}


def _rule(id: str, title: str, severity: str, why: str, fix: str) -> None:
    RULES[id] = Rule(id, title, severity, " ".join(why.split()), textwrap.dedent(fix).strip("\n"))


_rule(
    "WHK001",
    "Webhook handler does not verify the signature",
    "critical (Twilio: high)",
    """
A webhook URL is public: anyone who finds it (it is in your code, your logs, your
frontend bundle or simply guessable, like /api/webhooks/stripe) can POST to it. If the
handler acts on the body without checking the provider's signature, a forged
"checkout.session.completed" or "payment.captured" event unlocks a paid plan for free,
and a forged "user.deleted" deletes a real account.
""",
    """
Verify the provider's signature over the raw request body before reading the event,
and return 400 when it fails. Examples (Node, then Python):

  Stripe:    event = stripe.webhooks.constructEvent(rawBody, req.headers["stripe-signature"], secret)
             event = stripe.Webhook.construct_event(payload, sig_header, secret)
  Razorpay:  HMAC-SHA256(rawBody, webhook secret) as hex == X-Razorpay-Signature (timingSafeEqual)
             client.utility.verify_webhook_signature(payload.decode(), signature, secret)
  GitHub:    "sha256=" + HMAC-SHA256(rawBody, secret) as hex == X-Hub-Signature-256
  Svix/Clerk: new Webhook(secret).verify(rawBody, {svix-id, svix-timestamp, svix-signature})
  Shopify:   base64 HMAC-SHA256(rawBody, app secret) == X-Shopify-Hmac-Sha256

Run `webhook-check scan` to get the exact code for your provider and framework.
""",
)
_rule(
    "WHK002",
    "Signature checked against parsed / re-serialized JSON",
    "high",
    """
Providers sign the exact bytes they send. JSON.stringify(req.body) / json.dumps(data)
produces different bytes (key order, whitespace, unicode escapes like \\u00e9, number
formatting), so valid events fail verification at random. The usual "fix" is to turn the
check off or wrap it in a try/catch that carries on, which removes the protection. With
framework body parsers (express.json(), Next.js pages API, Fastify) the raw bytes are
gone before your handler runs.
""",
    """
Read the raw body, verify it, and only then JSON.parse it:

  Next.js App Router:  const rawBody = await req.text();
  Next.js pages/api:   export const config = { api: { bodyParser: false } }; then read the stream
  Express:             app.post(path, express.raw({ type: "application/json" }), handler)
                       registered BEFORE app.use(express.json())
  Hono:                const rawBody = await c.req.text();
  FastAPI:             payload = await request.body()
  Flask:               payload = request.get_data()
  Django:              payload = request.body
""",
)
_rule(
    "WHK003",
    "Signature compared with == instead of a constant-time comparison",
    "medium",
    """
`==` / `===` on strings stops at the first byte that differs, so the response time
tells an attacker how many leading characters of a guessed signature are right. Over
many requests that leaks a valid signature for a forged body. HMAC checks must use a
constant-time comparison.
""",
    """
Node:    const a = Buffer.from(expected), b = Buffer.from(received);
         if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return 400;
Python:  if not hmac.compare_digest(expected, received): return 400
""",
)
_rule(
    "WHK004",
    "Hard-coded webhook signing secret",
    "critical (whsec_ secrets) / high",
    """
The webhook secret is the only thing that separates a real event from a forged one.
Written into source code it is in git history, every clone, CI logs and often the
deployed bundle: anyone who has it can sign their own "payment succeeded" events.
""",
    """
1. Roll the secret in the provider dashboard now; assume the old value is public.
2. Read it from the environment / a secrets manager:
     Node:    const secret = process.env.STRIPE_WEBHOOK_SECRET;   // fail fast if missing
     Python:  secret = os.environ["STRIPE_WEBHOOK_SECRET"]
   Do not keep a hard-coded fallback (`process.env.X || "..."`, os.environ.get("X", "...")).
3. If it was committed, remove it from git history (git filter-repo / BFG).
""",
)
_rule(
    "WHK005",
    "Signature verification failure is ignored",
    "high",
    """
Verification only protects you if a failed check stops the request. A catch / except
block that logs and carries on, or a boolean check whose result is never used
(validateWebhookSignature(), timingSafeEqual(), hmac.compare_digest() return false
instead of throwing), lets a forged event through exactly as if there were no check.
""",
    """
Reject the request when verification fails:

  Node:    try { event = stripe.webhooks.constructEvent(rawBody, sig, secret); }
           catch (err) { return res.status(400).send("Invalid signature"); }
           if (!validateWebhookSignature(rawBody, sig, secret)) return res.status(400).end();
  Python:  except stripe.error.SignatureVerificationError:
               return HttpResponse(status=400)     # or raise HTTPException(400) / abort(400)
           if not hmac.compare_digest(expected, received): abort(400)
""",
)
_rule(
    "WHK006",
    "Razorpay payment trusted without verifying razorpay_signature",
    "critical",
    """
After Razorpay Checkout, the browser posts razorpay_payment_id, razorpay_order_id and
razorpay_signature to your server. Everything in that request comes from the client. If
the server marks the order paid without checking that razorpay_signature equals
HMAC-SHA256(order_id + "|" + payment_id, key_secret), anyone can post a made-up or
someone else's payment id (or a cheap payment against an expensive order) and get the
product.
""",
    """
Verify the signature against the order id YOU created and stored, then trust the amount
from your own order record (or fetch the payment from Razorpay), never from the client:

  Node:    const { validatePaymentVerification } = require("razorpay/dist/utils/razorpay-utils");
           const ok = validatePaymentVerification(
             { order_id: order.razorpayOrderId, payment_id: razorpay_payment_id },
             razorpay_signature, process.env.RAZORPAY_KEY_SECRET);
           if (!ok) return res.status(400).json({ error: "invalid signature" });
  Python:  client.utility.verify_payment_signature({
               "razorpay_order_id": order.razorpay_order_id,
               "razorpay_payment_id": payment_id,
               "razorpay_signature": signature})   # raises SignatureVerificationError
""",
)
_rule(
    "WHK007",
    "Webhook events are not de-duplicated",
    "low (heuristic)",
    """
Providers deliver at least once: retries after a timeout, manual "resend" from the
dashboard and replays of a captured request all deliver the same event again. A handler
that changes state without remembering which event ids it has processed can credit an
account twice, send duplicate emails or re-provision a subscription.
""",
    """
Record each event id before acting on it, with a unique constraint, and skip duplicates:

  SQL:     create table processed_webhook_events (id text primary key, received_at timestamptz default now());
  Node:    const { rowCount } = await db.query(
             "insert into processed_webhook_events (id) values ($1) on conflict do nothing", [event.id]);
           if (rowCount === 0) return res.status(200).end();   // already handled
  Python:  cur.execute("insert into processed_webhook_events (id) values (%s) on conflict do nothing", (event["id"],))
           if cur.rowcount == 0: return HttpResponse(status=200)
""",
)
_rule(
    "WHK008",
    "Stripe signature tolerance disabled or very large",
    "low",
    """
Stripe signs a timestamp together with the body and rejects events older than the
tolerance (default 300 seconds). This stops a captured request (from a log, a proxy or a
debugging session) from being replayed later. A tolerance of 0 / None disables the check
in the SDK; hours or days make replay practical.
""",
    """
Drop the tolerance argument to use Stripe's default of 300 seconds:

  Node:    stripe.webhooks.constructEvent(rawBody, sig, secret)
  Python:  stripe.Webhook.construct_event(payload, sig_header, secret)
""",
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    heuristic: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def location(self) -> str:
        if self.file is None:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def fix(self) -> str:
        """The fix written for this finding's provider, language and framework."""
        from .fixes import build_fix

        return build_fix(self.rule_id, self.extra) or self.rule.fix

    def to_dict(self) -> dict:
        d = asdict(self)
        d["title"] = self.rule.title
        d["why"] = self.rule.why
        d["fix"] = self.fix
        if not d["extra"]:
            d.pop("extra")
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.file or "", f.line or 0),
    )


def mask_secret(value: str) -> str:
    """Show at most the first 4 characters of a secret, never enough to use it."""
    keep = min(4, len(value) // 4)
    return f"{value[:keep]}**** ({len(value)} chars)"


# Token formats that are masked in any line we print, whatever rule reported it.
KNOWN_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Stripe/Svix webhook secret", re.compile(r"\bwhsec_[A-Za-z0-9+/=_\-]{8,}")),
    ("Stripe key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{10,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("Shopify secret", re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    ("Razorpay key", re.compile(r"\brzp_(?:live|test)_[A-Za-z0-9]{10,}")),
    ("Paddle key", re.compile(r"\bpdl_(?:live|sdbx|ntfset)_[A-Za-z0-9_]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
]


def redact_line(line: str, extra_secrets: list[str] | None = None, limit: int = 160) -> str:
    """Strip a source line for display, masking anything secret-shaped."""
    s = line.strip()
    for secret in sorted(extra_secrets or [], key=len, reverse=True):
        if secret and len(secret) >= 4:
            s = s.replace(secret, mask_secret(secret))
    for _, pat in KNOWN_SECRET_PATTERNS:
        s = pat.sub(lambda m: mask_secret(m.group(0)), s)
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s
