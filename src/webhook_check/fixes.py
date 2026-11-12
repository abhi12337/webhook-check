"""Fix text written for a finding's provider, language and framework.

Every snippet uses the provider's documented verification API or signature scheme:
  Stripe        Stripe-Signature; stripe.webhooks.constructEvent / stripe.Webhook.construct_event
  Razorpay      X-Razorpay-Signature = hex HMAC-SHA256(raw body, webhook secret);
                client.utility.verify_webhook_signature (Python SDK)
  GitHub        X-Hub-Signature-256 = "sha256=" + hex HMAC-SHA256(raw body, secret)
  Svix / Clerk  svix-id / svix-timestamp / svix-signature; new Webhook(secret).verify(payload, headers)
  Shopify       X-Shopify-Hmac-Sha256 = base64 HMAC-SHA256(raw body, app client secret)
  Paddle        Paddle-Signature "ts=...;h1=..." with h1 = hex HMAC-SHA256(ts + ":" + raw body, secret)
  Lemon Squeezy X-Signature = hex HMAC-SHA256(raw body, signing secret)
  Twilio        X-Twilio-Signature; twilio.validateRequest / RequestValidator.validate
  PayPal        POST /v1/notifications/verify-webhook-signature with the PAYPAL-* headers
"""

from __future__ import annotations

import textwrap

from .providers import BY_KEY

# ---------------------------------------------------------------- framework pieces
JS_REQ = {"hono": "c", "fastify": "request"}


def _hdr(lang: str, fw: str, name: str) -> str:
    if lang == "js":
        if fw in ("next-app", "deno"):
            return f'req.headers.get("{name}")'
        if fw == "hono":
            return f'c.req.header("{name}")'
        if fw == "fastify":
            return f'request.headers["{name}"]'
        return f'req.headers["{name}"]'
    title = "-".join(p.capitalize() if p not in ("sha256",) else p.capitalize() for p in name.split("-"))
    return f'request.headers.get("{title}", "")'


def _fail(lang: str, fw: str) -> str:
    if lang == "js":
        return {
            "next-app": 'return new Response("Invalid signature", { status: 400 });',
            "deno": 'return new Response("Invalid signature", { status: 400 });',
            "hono": 'return c.text("Invalid signature", 400);',
            "fastify": 'return reply.code(400).send("Invalid signature");',
            "nestjs": 'throw new BadRequestException("Invalid signature");',
            "koa": 'ctx.throw(400, "Invalid signature");',
        }.get(fw, 'return res.status(400).send("Invalid signature");')
    return {
        "fastapi": 'raise HTTPException(status_code=400, detail="Invalid signature")',
        "flask": "abort(400)",
        "django": "return HttpResponse(status=400)",
    }.get(fw, "return 400  # reject the request")


def raw_body(lang: str, fw: str, route: str = "") -> str:
    route = route or "/webhooks/provider"
    if lang == "js":
        return {
            "next-app": "const rawBody = await req.text();   // not req.json(): keep the exact bytes",
            "deno": "const rawBody = await req.text();   // not req.json(): keep the exact bytes",
            "hono": "const rawBody = await c.req.text();   // not c.req.json()",
            "express": (f'app.post("{route}", express.raw({{ type: "application/json" }}), handler);\n'
                        f"// register it BEFORE app.use(express.json()); in the handler:\n"
                        f"const rawBody = req.body;   // a Buffer"),
            "next-pages": ("export const config = { api: { bodyParser: false } };\n"
                           "// in the handler:\n"
                           "const chunks = [];\n"
                           "for await (const chunk of req) chunks.push(typeof chunk === \"string\" ? Buffer.from(chunk) : chunk);\n"
                           "const rawBody = Buffer.concat(chunks);"),
            "fastify": ('fastify.addContentTypeParser("application/json", { parseAs: "buffer" },\n'
                        "  (req, body, done) => done(null, body));   // inside the webhook route's plugin\n"
                        "const rawBody = request.body;   // a Buffer"),
            "nestjs": ("const app = await NestFactory.create(AppModule, { rawBody: true });\n"
                       "// handler: @Req() req: RawBodyRequest<Request>\n"
                       "const rawBody = req.rawBody;"),
            "koa": "const rawBody = await getRawBody(ctx.req);   // raw-body package, before any JSON body parser",
        }.get(fw, "const rawBody = /* the exact bytes received: a Buffer or string, before any JSON parsing */;")
    return {
        "fastapi": "payload = await request.body()",
        "flask": "payload = request.get_data()",
        "django": "payload = request.body",
    }.get(fw, "payload = <the raw request body bytes>")


def _ind(s: str, n: int = 2) -> str:
    return textwrap.indent(s, " " * n)


def verify_snippet(provider: str, lang: str, fw: str, route: str = "") -> str:
    h = lambda name: _hdr(lang, fw, name)  # noqa: E731
    fail = _fail(lang, fw)
    if lang == "js":
        cmp = lambda a, b: (f"const a = Buffer.from({a}), b = Buffer.from({b});\n"  # noqa: E731
                            f"if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {{\n  {fail}\n}}")
        if provider == "stripe":
            fn = "await stripe.webhooks.constructEventAsync" if fw in ("next-app", "hono", "deno") else \
                "stripe.webhooks.constructEvent"
            return (f"let event;\ntry {{\n  event = {fn}(rawBody, {h('stripe-signature')}, "
                    f"process.env.STRIPE_WEBHOOK_SECRET);\n}} catch (err) {{\n  {fail}\n}}")
        if provider == "razorpay":
            return ('import crypto from "crypto";\n'
                    f'const expected = crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)\n'
                    f'  .update(rawBody).digest("hex");\n' +
                    cmp("expected", f'String({h("x-razorpay-signature")} ?? "")') +
                    "\n// SDK alternative: validateWebhookSignature(rawBody.toString(), signature, secret) from\n"
                    '// "razorpay/dist/utils/razorpay-utils" (returns a boolean: check it)')
        if provider == "github":
            return ('import crypto from "crypto";\n'
                    'const expected = "sha256=" + crypto.createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET)\n'
                    '  .update(rawBody).digest("hex");\n' +
                    cmp("expected", f'String({h("x-hub-signature-256")} ?? "")') +
                    "\n// or @octokit/webhooks: if (!(await webhooks.verify(rawBody.toString(), signature))) reject")
        if provider == "svix":
            return ('import { Webhook } from "svix";\n'
                    "const wh = new Webhook(process.env.CLERK_WEBHOOK_SIGNING_SECRET);   // the whsec_... value\n"
                    "let evt;\ntry {\n  evt = wh.verify(rawBody, {\n"
                    f'    "svix-id": {h("svix-id")},\n'
                    f'    "svix-timestamp": {h("svix-timestamp")},\n'
                    f'    "svix-signature": {h("svix-signature")},\n'
                    f"  }});\n}} catch (err) {{\n  {fail}\n}}\n"
                    '// Clerk + Next.js: const evt = await verifyWebhook(req) from "@clerk/nextjs/webhooks"')
        if provider == "shopify":
            return ('import crypto from "crypto";\n'
                    'const digest = crypto.createHmac("sha256", process.env.SHOPIFY_API_SECRET)\n'
                    '  .update(rawBody).digest("base64");\n' +
                    cmp("digest", f'String({h("x-shopify-hmac-sha256")} ?? "")') +
                    "\n// @shopify/shopify-api: await shopify.webhooks.validate({ rawBody, rawRequest: req, rawResponse: res })"
                    "\n// Shopify Remix app: const { topic, shop, payload } = await authenticate.webhook(request);")
        if provider == "paddle":
            return ('import crypto from "crypto";\n'
                    f'const parts = Object.fromEntries(String({h("paddle-signature")} ?? "")\n'
                    '  .split(";").map((p) => p.split("=")));   // "ts=...;h1=..."\n'
                    'const expected = crypto.createHmac("sha256", process.env.PADDLE_WEBHOOK_SECRET)\n'
                    '  .update(`${parts.ts}:${rawBody}`).digest("hex");\n' +
                    cmp("expected", 'String(parts.h1 ?? "")') +
                    "\n// also reject old events: Math.abs(Date.now() / 1000 - Number(parts.ts)) > 5 * 60"
                    "\n// or @paddle/paddle-node-sdk: await paddle.webhooks.unmarshal(rawBody.toString(), secret, signature)")
        if provider == "lemonsqueezy":
            return ('import crypto from "crypto";\n'
                    'const digest = crypto.createHmac("sha256", process.env.LEMONSQUEEZY_WEBHOOK_SECRET)\n'
                    '  .update(rawBody).digest("hex");\n' +
                    cmp("digest", f'String({h("x-signature")} ?? "")'))
        if provider == "twilio":
            url = f"https://your-domain.example{route or '/sms'}"
            return ('import twilio from "twilio";\n'
                    f"const ok = twilio.validateRequest(process.env.TWILIO_AUTH_TOKEN, {h('x-twilio-signature')},\n"
                    f'  "{url}", req.body);   // the exact public URL Twilio calls\n'
                    f"if (!ok) {{\n  {fail}\n}}\n"
                    f'// Express: app.post("{route or "/sms"}", twilio.webhook(), handler)')
        if provider == "paypal":
            return ('const r = await fetch("https://api-m.paypal.com/v1/notifications/verify-webhook-signature", {\n'
                    '  method: "POST",\n'
                    '  headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },\n'
                    "  body: JSON.stringify({\n"
                    f'    auth_algo: {h("paypal-auth-algo")},\n'
                    f'    cert_url: {h("paypal-cert-url")},\n'
                    f'    transmission_id: {h("paypal-transmission-id")},\n'
                    f'    transmission_sig: {h("paypal-transmission-sig")},\n'
                    f'    transmission_time: {h("paypal-transmission-time")},\n'
                    "    webhook_id: process.env.PAYPAL_WEBHOOK_ID,\n"
                    "    webhook_event: JSON.parse(rawBody),\n"
                    "  }),\n});\n"
                    f'if ((await r.json()).verification_status !== "SUCCESS") {{\n  {fail}\n}}')
        return ""
    # ---- Python
    fail_i = _ind(fail, 4)
    cmp = lambda a, b: f"if not hmac.compare_digest({a}, {b}):\n{fail_i}"  # noqa: E731
    if provider == "stripe":
        return ("import stripe\n"
                "try:\n"
                f"    event = stripe.Webhook.construct_event(\n"
                f"        payload, {h('stripe-signature')}, os.environ[\"STRIPE_WEBHOOK_SECRET\"])\n"
                "except (ValueError, stripe.error.SignatureVerificationError):\n" + fail_i)
    if provider == "razorpay":
        return ("import razorpay\n"
                "try:\n"
                "    client.utility.verify_webhook_signature(\n"
                f"        payload.decode(), {h('x-razorpay-signature')}, os.environ[\"RAZORPAY_WEBHOOK_SECRET\"])\n"
                "except razorpay.errors.SignatureVerificationError:\n" + fail_i)
    if provider == "github":
        return ("import hashlib, hmac\n"
                'expected = "sha256=" + hmac.new(\n'
                '    os.environ["GITHUB_WEBHOOK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()\n' +
                cmp("expected", h("x-hub-signature-256")))
    if provider == "svix":
        return ("from svix.webhooks import Webhook, WebhookVerificationError\n"
                "try:\n"
                '    evt = Webhook(os.environ["CLERK_WEBHOOK_SIGNING_SECRET"]).verify(payload, {\n'
                f'        "svix-id": {h("svix-id")},\n'
                f'        "svix-timestamp": {h("svix-timestamp")},\n'
                f'        "svix-signature": {h("svix-signature")},\n'
                "    })\n"
                "except WebhookVerificationError:\n" + fail_i)
    if provider == "shopify":
        return ("import base64, hashlib, hmac\n"
                "digest = base64.b64encode(hmac.new(\n"
                '    os.environ["SHOPIFY_API_SECRET"].encode(), payload, hashlib.sha256).digest()).decode()\n' +
                cmp("digest", h("x-shopify-hmac-sha256")))
    if provider == "paddle":
        return ("import hashlib, hmac, time\n"
                f'parts = dict(p.split("=", 1) for p in {h("paddle-signature")}.split(";") if "=" in p)\n'
                'signed = parts.get("ts", "").encode() + b":" + payload\n'
                'expected = hmac.new(os.environ["PADDLE_WEBHOOK_SECRET"].encode(), signed, hashlib.sha256).hexdigest()\n'
                'if not hmac.compare_digest(expected, parts.get("h1", "")) or \\\n'
                '        abs(time.time() - int(parts.get("ts", "0"))) > 300:\n' + fail_i)
    if provider == "lemonsqueezy":
        return ("import hashlib, hmac\n"
                'digest = hmac.new(os.environ["LEMONSQUEEZY_WEBHOOK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()\n' +
                cmp("digest", h("x-signature")))
    if provider == "twilio":
        form, url = {"fastapi": ("dict(await request.form())", "str(request.url)"),
                     "django": ("request.POST", "request.build_absolute_uri()")}.get(fw, ("request.form", "request.url"))
        return ("from twilio.request_validator import RequestValidator\n"
                'validator = RequestValidator(os.environ["TWILIO_AUTH_TOKEN"])\n'
                f"if not validator.validate({url}, {form}, {h('x-twilio-signature')}):\n" + fail_i +
                "\n# behind a proxy, rebuild the public https URL Twilio called")
    if provider == "paypal":
        return ("r = requests.post(\n"
                '    "https://api-m.paypal.com/v1/notifications/verify-webhook-signature",\n'
                '    headers={"Authorization": f"Bearer {access_token}"},\n'
                "    json={\n"
                f'        "auth_algo": {h("paypal-auth-algo")},\n'
                f'        "cert_url": {h("paypal-cert-url")},\n'
                f'        "transmission_id": {h("paypal-transmission-id")},\n'
                f'        "transmission_sig": {h("paypal-transmission-sig")},\n'
                f'        "transmission_time": {h("paypal-transmission-time")},\n'
                '        "webhook_id": os.environ["PAYPAL_WEBHOOK_ID"],\n'
                '        "webhook_event": json.loads(payload),\n'
                "    }, timeout=10)\n"
                'if r.json().get("verification_status") != "SUCCESS":\n' + fail_i)
    return ""


def _ignore_fix(extra: dict) -> str:
    lang, fw = extra.get("lang", "js"), extra.get("framework", "")
    fail = _fail(lang, fw)
    if extra.get("kind") == "ignored":
        call = extra.get("call", "the check")
        if lang == "js":
            return (f"Use the boolean it returns and stop on false:\n\n"
                    f"  if (!{call}(/* same arguments */)) {{\n    {fail}\n  }}")
        return f"Use the boolean it returns and stop on False:\n\n  if not {call}(...):\n      {fail}"
    if lang == "js":
        return ("Return (or throw) from the catch block so nothing after it runs, and never fall back to the\n"
                "unverified body:\n\n"
                f"  let event;\n  try {{\n    event = /* verification call */;\n  }} catch (err) {{\n"
                f"    console.warn(\"webhook signature verification failed\", err.message);\n    {fail}\n  }}")
    return ("Return (or raise) from the except block so nothing after it runs, and never fall back to the\n"
            "unverified body:\n\n"
            "  try:\n      event = ...  # verification call\n  except <VerificationError>:\n"
            f"      logger.warning(\"webhook signature verification failed\")\n      {fail}")


def build_fix(rule_id: str, extra: dict) -> str | None:
    if not extra:
        return None
    lang = extra.get("lang", "js")
    fw = extra.get("framework") or ("node" if lang == "js" else "python")
    prov = extra.get("provider")
    route = extra.get("route") or ""
    p = BY_KEY.get(prov) if prov else None
    if rule_id == "WHK001" and p:
        steps = []
        if p.raw_body:
            steps.append("1. Read the raw body (the exact bytes " + p.label + " signed):\n\n" +
                         _ind(raw_body(lang, fw, route), 5))
            steps.append(f"2. Verify the signature in {p.header} and reject on failure:\n\n" +
                         _ind(verify_snippet(p.key, lang, fw, route), 5))
            steps.append("3. Only then parse the JSON and act on the event. Keep the secret in an environment\n"
                         "   variable, never in code.")
        else:
            steps.append(f"Verify the signature in {p.header} and reject on failure:\n\n" +
                         _ind(verify_snippet(p.key, lang, fw, route), 5))
        return "\n\n".join(steps)
    if rule_id == "WHK002":
        out = ["Verify the raw bytes, then parse:\n\n" + _ind(raw_body(lang, fw, route), 5)]
        if p and p.raw_body:
            out.append(f"Then verify with {p.label}'s scheme:\n\n" + _ind(verify_snippet(p.key, lang, fw, route), 5))
        else:
            out.append("Pass rawBody (Buffer / string) or payload (bytes) to the verification call, and call\n"
                       "JSON.parse / json.loads only after it succeeds.")
        return "\n\n".join(out)
    if rule_id == "WHK003":
        var = extra.get("var") or "expected"
        var = "expected" if var == "HMAC digest" else var
        other = extra.get("other") or "received"
        if lang == "js":
            return (f"Compare in constant time (lengths first, timingSafeEqual throws on different lengths):\n\n"
                    f"  const a = Buffer.from({var}), b = Buffer.from(String({other} ?? \"\"));\n"
                    f"  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {{\n    {_fail(lang, fw)}\n  }}")
        return (f"Compare in constant time:\n\n  if not hmac.compare_digest({var}, {other}):\n"
                f"      {_fail(lang, fw)}")
    if rule_id == "WHK004":
        var = extra.get("var") or "WEBHOOK_SECRET"
        env = var if var.isupper() else "WEBHOOK_SECRET"
        if lang == "js":
            read = (f"  const secret = process.env.{env};\n"
                    f"  if (!secret) throw new Error(\"{env} is not set\");   // no hard-coded fallback")
        else:
            read = f'  secret = os.environ["{env}"]   # KeyError at startup beats a known secret'
        return ("1. Roll the secret in the provider's dashboard now: the committed value must be treated as public.\n"
                "2. Read it from the environment / your secrets manager:\n\n" + read + "\n\n"
                "3. If it was committed, remove it from git history (git filter-repo / BFG); rolling it is what\n"
                "   actually protects you.")
    if rule_id == "WHK005":
        return _ignore_fix(extra)
    if rule_id == "WHK006":
        fail = _fail(lang, fw)
        if lang == "js":
            return ("Verify razorpay_signature against the order id you created and stored (never the one the\n"
                    "client sends back), then use the amount from your own order record:\n\n"
                    '  import crypto from "crypto";\n'
                    "  const { razorpay_payment_id, razorpay_signature } = req.body;\n"
                    "  const order = await Order.findOne({ user: req.user.id, status: \"created\" });   // your record\n"
                    '  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)\n'
                    '    .update(order.razorpayOrderId + "|" + razorpay_payment_id).digest("hex");\n'
                    '  const a = Buffer.from(expected), b = Buffer.from(String(razorpay_signature ?? ""));\n'
                    f"  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {{\n    {fail}\n  }}\n\n"
                    "SDK: validatePaymentVerification({ order_id, payment_id }, signature, key_secret) from\n"
                    '"razorpay/dist/utils/razorpay-utils". Also handle the payment.captured webhook as the\n'
                    "source of truth: the browser callback never arrives if the tab is closed.")
        return ("Verify razorpay_signature against the order id you created and stored (never the one the\n"
                "client sends back), then use the amount from your own order record:\n\n"
                "  client.utility.verify_payment_signature({\n"
                "      \"razorpay_order_id\": order.razorpay_order_id,   # from your database\n"
                "      \"razorpay_payment_id\": payment_id,\n"
                "      \"razorpay_signature\": signature,\n"
                "  })   # raises razorpay.errors.SignatureVerificationError\n\n"
                "Also handle the payment.captured webhook as the source of truth: the browser callback never\n"
                "arrives if the tab is closed.")
    if rule_id == "WHK007" and p:
        where = p.event_id
        if lang == "js":
            return (f"Record the event id ({where}) with a unique constraint before acting, and skip repeats:\n\n"
                    "  // create table processed_webhook_events (id text primary key, received_at timestamptz default now());\n"
                    "  const { rowCount } = await db.query(\n"
                    "    \"insert into processed_webhook_events (id) values ($1) on conflict do nothing\", [eventId]);\n"
                    "  if (rowCount === 0) return /* 200: already handled */;\n\n"
                    "Do the insert in the same transaction as the state change, so a crash cannot record the\n"
                    "event without applying it.")
        return (f"Record the event id ({where}) with a unique constraint before acting, and skip repeats:\n\n"
                "  # create table processed_webhook_events (id text primary key, received_at timestamptz default now());\n"
                "  cur.execute(\"insert into processed_webhook_events (id) values (%s) on conflict do nothing\", (event_id,))\n"
                "  if cur.rowcount == 0:\n      return  # 200: already handled\n\n"
                "Django: ProcessedEvent.objects.get_or_create(id=event_id) inside transaction.atomic().")
    if rule_id == "WHK008":
        if lang == "js":
            return ("Remove the tolerance argument so Stripe's default (300 seconds) applies:\n\n"
                    "  event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET);")
        return ("Remove the tolerance argument so Stripe's default (300 seconds) applies:\n\n"
                "  event = stripe.Webhook.construct_event(payload, sig_header, os.environ[\"STRIPE_WEBHOOK_SECRET\"])")
    return None
