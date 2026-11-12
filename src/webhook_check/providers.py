"""Webhook providers: how a handler for each is recognised and what counts as verification.

Only providers whose signature scheme is documented precisely are included. Supabase
database webhooks are left out on purpose: they carry whatever headers you configure,
so there is no standard signature to look for."""

from __future__ import annotations

import re
from dataclasses import dataclass

_I = re.I


@dataclass(frozen=True)
class Provider:
    key: str
    label: str
    header: str                    # where the signature arrives, as documented
    severity: str                  # severity of WHK001 for this provider
    strong: re.Pattern[str]        # in the handler: this is certainly a <provider> webhook
    path: re.Pattern[str]          # route path / function name mentions the provider
    sdk: re.Pattern[str]           # the file mentions the provider at all
    events: re.Pattern[str] | None  # event-type strings (only trusted together with `sdk`)
    file_strong: re.Pattern[str] | None  # an import that only webhook code uses
    verify: re.Pattern[str]        # provider-specific verification calls
    dedupe: re.Pattern[str] | None  # provider-specific event / delivery id
    event_id: str                  # where the event id is, for the WHK007 fix
    impact: str                    # what a forged event does, for messages
    raw_body: bool = True          # signature is over the raw body (WHK002 applies)


PROVIDERS: list[Provider] = [
    Provider(
        key="stripe", label="Stripe", header="Stripe-Signature", severity="critical",
        strong=re.compile(r"stripe[-_]signature|\bconstructEvent(?:Async)?\b|\bconstruct_event\b|"
                          r"\bstripe\.Webhook\b|\bWebhookSignature\b", _I),
        path=re.compile(r"stripe", _I),
        sdk=re.compile(r"stripe", _I),
        events=re.compile(r"""['"](?:checkout\.session|payment_intent|invoice|customer\.subscription|charge|"""
                          r"""setup_intent|payment_method|subscription_schedule|payout)\.[a-z_.]+['"]"""),
        file_strong=None,
        verify=re.compile(r"\bconstructEvent(?:Async)?\s*\(|\bconstruct_event\s*\(|\bverify_header\s*\("),
        dedupe=None,
        event_id="event.id",
        impact="a forged 'checkout.session.completed' / 'invoice.paid' marks an order or subscription paid",
    ),
    Provider(
        key="razorpay", label="Razorpay", header="X-Razorpay-Signature", severity="critical",
        strong=re.compile(r"x[-_]razorpay[-_]signature|x[-_]razorpay[-_]event[-_]id|\bvalidateWebhookSignature\b|"
                          r"\bverify_webhook_signature\b", _I),
        path=re.compile(r"razorpay|\brzp", _I),
        sdk=re.compile(r"razorpay", _I),
        events=re.compile(r"""['"](?:payment\.(?:authorized|captured|failed)|order\.paid|"""
                          r"""subscription\.(?:authenticated|activated|charged|completed|cancelled|halted|paused|"""
                          r"""pending|resumed)|refund\.(?:created|processed|failed)|payment_link\.paid|"""
                          r"""invoice\.paid)['"]"""),
        file_strong=None,
        verify=re.compile(r"\bvalidateWebhookSignature\s*\(|\bverify_webhook_signature\s*\("),
        dedupe=re.compile(r"x[-_]razorpay[-_]event[-_]id", _I),
        event_id="the X-Razorpay-Event-Id header",
        impact="a forged 'payment.captured' / 'order.paid' marks an order paid",
    ),
    Provider(
        key="github", label="GitHub", header="X-Hub-Signature-256", severity="critical",
        strong=re.compile(r"x[-_]github[-_]event|x[-_]hub[-_]signature|x[-_]github[-_]delivery|x[-_]github[-_]hook[-_]id", _I),
        path=re.compile(r"github|gh[-_]?hook", _I),
        sdk=re.compile(r"github|octokit", _I),
        events=None,
        file_strong=re.compile(r"""@octokit/webhooks"""),
        verify=re.compile(r"\bwebhooks\s*\.\s*(?:verify|verifyAndReceive)\s*\(|\bverifyAndReceive\s*\(|"
                          r"\bcreateNodeMiddleware\s*\(|\bverify\s*\("),
        dedupe=re.compile(r"x[-_]github[-_]delivery", _I),
        event_id="the X-GitHub-Delivery header",
        impact="a forged push / release / workflow_run event triggers your deploy or automation",
    ),
    Provider(
        key="svix", label="Clerk/Svix", header="svix-signature (with svix-id and svix-timestamp)",
        severity="critical",
        strong=re.compile(r"svix[-_](?:id|timestamp|signature)|\bverifyWebhook\s*\(", _I),
        path=re.compile(r"clerk|svix", _I),
        sdk=re.compile(r"clerk|svix", _I),
        events=re.compile(r"""['"](?:user|session|organization|organizationMembership|organizationInvitation|"""
                          r"""email|sms|role|permission)\.(?:created|updated|deleted|ended|removed|revoked)['"]"""),
        file_strong=re.compile(r"""(?:from|import)\s+['"]svix['"]|require\(\s*['"]svix['"]\s*\)|"""
                               r"""^\s*(?:from\s+svix|import\s+svix)\b|@clerk/[\w/-]*webhooks""", re.M),
        verify=re.compile(r"\.\s*verify\s*\(|\bverifyWebhook\s*\("),
        dedupe=re.compile(r"svix[-_]id|webhook[-_]id", _I),
        event_id="the svix-id header",
        impact="a forged 'user.created' / 'user.deleted' creates, changes or deletes accounts",
    ),
    Provider(
        key="shopify", label="Shopify", header="X-Shopify-Hmac-Sha256", severity="critical",
        strong=re.compile(r"x[-_]shopify[-_](?:hmac[-_]sha256|topic|shop[-_]domain|webhook[-_]id|event[-_]id|api[-_]version)|"
                          r"\bauthenticate\s*\.\s*webhook\s*\(", _I),
        path=re.compile(r"shopify", _I),
        sdk=re.compile(r"shopify", _I),
        events=re.compile(r"""['"](?:orders|products|customers|app|carts|checkouts|refunds|app_subscriptions|"""
                          r"""inventory_levels|fulfillments|shop|customers_data_request|customers_redact|"""
                          r"""shop_redact)/[a-z_]+['"]"""),
        file_strong=None,
        verify=re.compile(r"\bwebhooks\s*\.\s*validate\s*\(|\bauthenticate\s*\.\s*webhook\s*\(|"
                          r"\bvalidateHmac\s*\(|\bverify_webhook\s*\("),
        dedupe=re.compile(r"x[-_]shopify[-_](?:webhook|event)[-_]id", _I),
        event_id="the X-Shopify-Webhook-Id header",
        impact="a forged 'orders/paid' / 'app/uninstalled' event changes orders or deletes shop data",
    ),
    Provider(
        key="paddle", label="Paddle", header="Paddle-Signature", severity="critical",
        strong=re.compile(r"paddle[-_]signature|\bwebhooks\s*\.\s*unmarshal\b|paddle_billing\.Notifications", _I),
        path=re.compile(r"paddle", _I),
        sdk=re.compile(r"paddle", _I),
        events=re.compile(r"""['"](?:transaction|subscription|customer|adjustment|address|business)\."""
                          r"""(?:completed|created|updated|paid|canceled|activated|past_due|billed|ready|"""
                          r"""payment_failed|trialing|paused|resumed)['"]"""),
        file_strong=None,
        verify=re.compile(r"\.\s*unmarshal\s*\(|\bisSignatureValid\s*\(|\bVerifier\s*\(\s*\)\s*\.\s*verify\s*\("),
        dedupe=re.compile(r"notification_id|notificationId", _I),
        event_id="event_id in the body",
        impact="a forged 'transaction.completed' / 'subscription.activated' grants a paid plan",
    ),
    Provider(
        key="lemonsqueezy", label="Lemon Squeezy", header="X-Signature", severity="critical",
        strong=re.compile(r"x[-_]event[-_]name|meta\s*\.\s*event_name|\[\s*['\"]meta['\"]\s*\]\s*\[\s*['\"]event_name|"
                          r"lemon-?squeezy|lemon_squeezy", _I),
        path=re.compile(r"lemon", _I),
        sdk=re.compile(r"lemon", _I),
        events=re.compile(r"""['"](?:order_created|order_refunded|subscription_(?:created|updated|cancelled|"""
                          r"""resumed|expired|paused|unpaused|payment_success|payment_failed|payment_recovered|"""
                          r"""payment_refunded|plan_changed)|license_key_(?:created|updated))['"]"""),
        file_strong=None,
        verify=re.compile(r"(?!x)x"),     # no SDK helper: an HMAC (generic check) is required
        dedupe=None,
        event_id="data.id + meta.event_name; Lemon Squeezy sends no delivery id",
        impact="a forged 'order_created' / 'subscription_created' grants a paid plan",
    ),
    Provider(
        key="twilio", label="Twilio", header="X-Twilio-Signature", severity="high",
        strong=re.compile(r"x[-_]twilio[-_]signature|\bMessagingResponse\b|\bVoiceResponse\b|\btwiml\b", _I),
        path=re.compile(r"twilio", _I),
        sdk=re.compile(r"twilio", _I),
        events=None,
        file_strong=None,
        verify=re.compile(r"\bvalidateRequest\w*\s*\(|\btwilio\s*\.\s*webhook\s*\(|\bRequestValidator\s*\(|"
                          r"\bvalidate_twilio_request\b|\bvalidateExpressRequest\s*\("),
        dedupe=None,
        event_id="MessageSid / CallSid",
        impact="forged inbound messages or calls trigger replies (billed to you) and actions",
        raw_body=False,
    ),
    Provider(
        key="paypal", label="PayPal", header="PAYPAL-TRANSMISSION-SIG (with the other PAYPAL-* headers)",
        severity="critical",
        strong=re.compile(r"paypal[-_]transmission[-_](?:id|sig|time)|paypal[-_]cert[-_]url|paypal[-_]auth[-_]algo|"
                          r"verify[-_]webhook[-_]signature", _I),
        path=re.compile(r"paypal", _I),
        sdk=re.compile(r"paypal", _I),
        events=re.compile(r"""['"](?:PAYMENT\.(?:CAPTURE|SALE|AUTHORIZATION)\.[A-Z_]+|CHECKOUT\.ORDER\.[A-Z_]+|"""
                          r"""BILLING\.SUBSCRIPTION\.[A-Z_]+)['"]"""),
        file_strong=None,
        verify=re.compile(r"verify-webhook-signature|\bverifyWebhookSignature\s*\(|\bverify_webhook_signature\s*\(|"
                          r"\bcreateVerify\s*\(|\bcrypto\s*\.\s*verify\s*\("),
        dedupe=None,
        event_id="the event id",
        impact="a forged 'PAYMENT.CAPTURE.COMPLETED' marks an order paid",
        raw_body=False,
    ),
]
BY_KEY = {p.key: p for p in PROVIDERS}

# A call whose name says it verifies a signature / webhook (local or imported helper).
# Checked on code with string contents blanked, so log messages never match.
GENERIC_VERIFY_RE = re.compile(
    r"""(?ix)
    \b(?:createHmac|timingSafeEqual|compare_digest|hmac\s*\.\s*new|hmac\s*\.\s*digest|hmac\s*\.\s*HMAC|
         subtle\s*\.\s*(?:verify|sign))\s*\(
  | (?<![\w$])[\w$]*(?:verif|valid|authenticat|check(?!out))[\w$]*
        (?:sig|webhook|hmac|hook|payload|stripe|razorpay|github|shopify|svix|clerk|paddle|lemon|twilio|paypal)
        [\w$]*\s*\(
  | (?<![\w$])[\w$]*(?:sig|webhook|hmac|hook|stripe|razorpay|github|shopify|svix|clerk|paddle|lemon|twilio|paypal)
        [\w$]*(?:verif|valid|check(?!out))[\w$]*\s*\(
  | (?<![\w$.])(?:verify|validate|authenticate)[\w$]*\s*\(\s*(?:await\s+)?
        (?:req|request|raw[\w$]*|body|payload|event|ctx|c)\b
  | \.\s*verify[\w$]*\s*\(
    """
)

WEBHOOKISH_RE = re.compile(r"hook|callback|notif|\bipn\b|/events?\b|_events?\b", _I)

# Event-id / idempotency evidence (WHK007).
DEDUPE_RE = re.compile(
    r"""(?ix)
    idempot | dedup | \bevent_?id\b | \beventid | delivery_?id | webhook_?id | processed_?(?:events|webhooks)
  | already_?(?:processed|handled|seen) | on\s+conflict | ignore_?conflicts | \bupsert | get_or_create
  | \b(?:event|evt|e|payload|body|data|notification|webhook|wh_event|stripe_event)\s*
        (?:\.\s*id\b | \[\s*['"]id['"]\s*\] | \.get\(\s*['"]id['"])
    """
)

# State changes (WHK007). Lines that compute an HMAC / hash are ignored first.
WRITE_CALL_RE = re.compile(
    r"""(?x)
    (?:(?<![\w$])([A-Za-z_$][\w$]*)\s*\.\s*|\)\s*\.\s*)
    (?:insert|insertOne|insertMany|insert_one|insert_many|update|updateOne|updateMany|update_one|update_many|
       upsert|create|createMany|save|delete|deleteOne|deleteMany|delete_one|delete_many|destroy|increment|
       decrement|bulk_create|add|commit|execute|query|rpc|send_mail|send_email|sendMail|sendEmail|enqueue|
       publish|set|put)\s*\(
  | \.\s*from\s*\(\s*['"]
  | (?<![\w$.])(?:fulfill|grant|credit|provision|activate|upgrade|downgrade|unlock|deliver|refund|cancel|ship|
       mark|record|send|create|save|store|insert|update|handle|process|sync|issue|give|add|delete|remove)
       (?:[A-Z_][\w$]*)?\s*\(
    """
)
WRITE_IGNORE_RECEIVERS = {
    "res", "reply", "resp", "response", "c", "ctx", "hmac", "hash", "h", "crypto", "console", "logger", "log",
    "JSON", "Buffer", "Array", "Object", "headers", "params", "url", "searchParams", "Math", "Date", "String",
    "Number", "Promise", "app", "router", "req", "request", "self", "this", "logging", "json", "os", "re",
    "hashlib", "base64", "parts", "chunks", "body", "signature", "sig", "seen", "set", "map", "cache",
}
WRITE_IGNORE_NAMES = re.compile(r"^(?:create(?:Hmac|Hash|Verify|Sign|Server|Client|App|Router|Route|ReadStream|"
                                r"Error|Element|Context|Response|Request)|handle|process)$")
HASH_LINE_RE = re.compile(r"hmac|createHash|hashlib|digest|crypto|signature", _I)


def has_write(text: str) -> bool:
    for line in text.splitlines():
        if HASH_LINE_RE.search(line):
            continue
        for m in WRITE_CALL_RE.finditer(line):
            recv = m.group(1)
            if recv and recv in WRITE_IGNORE_RECEIVERS:
                continue
            name = re.match(r"(?:[\w$]+\s*\.\s*|\)\s*\.\s*)?([\w$]+)", m.group(0).lstrip(".( \t"))
            if name and WRITE_IGNORE_NAMES.match(name.group(1)):
                continue
            return True
    return False


def first_event(text: str, p: Provider) -> str | None:
    if p.events is None:
        return None
    m = p.events.search(text)
    return m.group(0).strip("'\"") if m else None


def identify(context: str, label: str, file_text: str, *, explicit_route: bool) -> tuple[Provider | None, str]:
    """Which provider a handler serves, and how sure we are ("strong" / "events" / "path").

    `explicit_route` is True for a registered POST route (Express/Next/FastAPI/...). Plain
    functions are only accepted on strong evidence or event types plus the provider SDK."""
    best, best_n = None, 0
    for p in PROVIDERS:
        n = len(p.strong.findall(context))
        if p.file_strong is not None and p.file_strong.search(file_text):
            n += 1
        if n > best_n:
            best, best_n = p, n
    if best is not None:
        return best, "strong"
    for p in PROVIDERS:
        if p.events is not None and p.events.search(context) and p.sdk.search(file_text):
            return p, "events"
    if not explicit_route:
        return None, ""
    for p in PROVIDERS:
        if p.path.search(label) and WEBHOOKISH_RE.search(label):
            return p, "path"
    if WEBHOOKISH_RE.search(label):
        mentioned = [p for p in PROVIDERS if p.sdk.search(file_text)]
        if len(mentioned) == 1:
            return mentioned[0], "path"
    return None, ""
