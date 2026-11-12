# webhook-check

A static check for webhook handlers. A webhook URL is public, so the only thing that stops
anyone from POSTing a fake "payment succeeded" event to it is the provider's signature.
webhook-check reads your Node/TypeScript and Python code and finds the handlers that:

- process provider events **without verifying the signature** at all
- verify against `JSON.stringify(req.body)` / `json.dumps(data)` / an already-parsed body
  instead of the **raw bytes** that were signed (so verification breaks and gets switched off)
- compare HMACs with `==` / `===` instead of a **constant-time** comparison
- **hard-code the webhook secret** (or keep a hard-coded fallback)
- **catch a failed verification and carry on**, or ignore a boolean check's result
- mark a **Razorpay order paid from the browser callback** without checking `razorpay_signature`
- never **de-duplicate events**, or **widen Stripe's replay window**

Providers: **Stripe, Razorpay, GitHub, Clerk / Svix, Shopify, Paddle (Billing), Lemon Squeezy,
Twilio, PayPal**. Frameworks: Next.js (App Router route handlers and `pages/api`), Express,
Hono, Fastify, NestJS, Koa-style routers, Deno / Supabase Edge Functions, plain Lambda-style
handlers, FastAPI / Starlette, Flask, Django / DRF.

Every finding has a rule id, a severity, `file:line`, the offending line (secrets masked to
at most 4 characters), why it matters, and a fix written for **that provider and that
framework** (raw-body handling, header access and error response included).

Zero dependencies (Python 3.10+ standard library only). **Static only:** it never runs your
code, never imports it and makes no network requests. CI-friendly exit codes.

---

## Quick start

```bash
pipx install git+https://github.com/abhi12337/webhook-check   # straight from GitHub
pipx install .                            # from a clone of this repo (or: pip install .)

webhook-check scan                        # current folder
webhook-check scan path/to/app path/to/api
webhook-check scan app/api/webhooks/stripe/route.ts     # a single file
webhook-check scan . --json > report.json # machine-readable output
webhook-check rules                       # every rule, why it matters, how to fix it
```

Try it on the deliberately broken demo project (a Next.js + Express + Hono app and a
FastAPI + Flask + Django backend, copied from `tests/fixtures`):

```bash
python examples/make_demo.py demo-webhooks
webhook-check scan demo-webhooks
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = findings at or above
it, `2` = usage error. Use `--fail-on critical|high|medium|low|info|never` to tune CI.

## Example output

All output below was produced by running this version of the tool on the demo project and the
test fixtures in this repository (nothing is hand-edited).

`webhook-check scan demo-webhooks/web/server/express.ts --brief` (one Express server):

```text
webhook-check 0.1.1
Scanned demo-webhooks/web/server/express.ts
1 source file(s), 4 webhook handler(s) (GitHub 1, Razorpay 1, Shopify 1, Stripe 1), 1 Razorpay payment-verification endpoint(s)

CRITICAL WHK001  Webhook handler does not verify the signature
      at: demo-webhooks/web/server/express.ts:61
      POST /webhooks/shopify/orders-create handles Shopify webhook events but never verifies the
      signature in X-Shopify-Hmac-Sha256: anyone who can reach this URL can send a forged event; a
      forged 'orders/paid' / 'app/uninstalled' event changes orders or deletes shop data.
      code: app.post("/webhooks/shopify/orders-create", async (req, res) => {

CRITICAL WHK006  Razorpay payment trusted without verifying razorpay_signature
      at: demo-webhooks/web/server/express.ts:55
      POST /api/payment/verify reads razorpay_payment_id from the client (Razorpay Checkout
      callback) and never verifies razorpay_signature = HMAC-SHA256(order_id + "|" + payment_id,
      key_secret): anyone can post a made-up or reused payment id and get the order marked paid.
      code: const { razorpay_order_id, razorpay_payment_id } = req.body;

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: demo-webhooks/web/server/express.ts:17
      GitHub signature is checked in crypto.createHmac().update() against JSON.stringify(...) (re-
      serialized JSON), not the raw bytes that were signed: key order, spacing and unicode escapes
      differ, so real events fail and the check tends to get disabled.
      code: const digest = "sha256=" + crypto.createHmac("sha256", GITHUB_WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest("hex");

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: demo-webhooks/web/server/express.ts:28
      Stripe signature is checked in stripe.webhooks.constructEvent() against req.body, but
      express.json() is registered first (line 10), so req.body is a parsed object here; a route-
      level express.raw() cannot undo that.
      code: event = stripe.webhooks.constructEvent(

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: demo-webhooks/web/server/express.ts:46
      Razorpay signature is checked in validateWebhookSignature() against JSON.stringify(...) (re-
      serialized JSON), not the raw bytes that were signed: key order, spacing and unicode escapes
      differ, so real events fail and the check tends to get disabled. JSON.stringify(req.body) is
      a widely copied Razorpay pattern; it only works while Razorpay's serialisation happens to
      match JSON.stringify's.
      code: validateWebhookSignature(JSON.stringify(req.body), req.headers["x-razorpay-signature"] as string, process.env.RAZORPAY_WEBHOOK_SECRET as string);

HIGH     WHK004  Hard-coded webhook signing secret
      at: demo-webhooks/web/server/express.ts:12
      Webhook signing secret hard-coded in GITHUB_WEBHOOK_SECRET: anyone with the source can sign
      forged events. Value: gh-h**** (24 chars).
      code: const GITHUB_WEBHOOK_SECRET = "gh-h**** (24 chars)";

HIGH     WHK005  Signature verification failure is ignored
      at: demo-webhooks/web/server/express.ts:34
      Signature verification failure is caught and the handler carries on: this catch block
      neither returns nor throws, and it falls back to the unverified body, so a forged event is
      processed anyway.
      code: } catch (err) {

HIGH     WHK005  Signature verification failure is ignored
      at: demo-webhooks/web/server/express.ts:46
      The result of validateWebhookSignature() is ignored: it returns false for a bad signature
      instead of throwing, so this line verifies nothing.
      code: validateWebhookSignature(JSON.stringify(req.body), req.headers["x-razorpay-signature"] as string, process.env.RAZORPAY_WEBHOOK_SECRET as string);

MEDIUM   WHK003  Signature compared with == instead of a constant-time comparison
      at: demo-webhooks/web/server/express.ts:18
      HMAC signature `digest` is compared with '===': a non-constant-time comparison leaks how
      much of a forged signature is right (timing attack).
      code: if (sig === digest && req.get("x-github-event") === "push") {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: demo-webhooks/web/server/express.ts:25
      POST /webhooks/stripe changes state for Stripe events but never records the event id
      (event.id): retries, dashboard re-sends and replays apply the same event twice.
      code: app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: demo-webhooks/web/server/express.ts:45
      POST /webhooks/razorpay changes state for Razorpay events but never records the event id
      (the X-Razorpay-Event-Id header): retries, dashboard re-sends and replays apply the same
      event twice.
      code: app.post("/webhooks/razorpay", async (req, res) => {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: demo-webhooks/web/server/express.ts:61
      POST /webhooks/shopify/orders-create changes state for Shopify events but never records the
      event id (the X-Shopify-Webhook-Id header): retries, dashboard re-sends and replays apply
      the same event twice.
      code: app.post("/webhooks/shopify/orders-create", async (req, res) => {

LOW      WHK008  Stripe signature tolerance disabled or very large
      at: demo-webhooks/web/server/express.ts:32
      Stripe signature tolerance is 60 * 60 * 24 * 30 = 2592000 seconds instead of the default
      300: a captured event (from logs or a proxy) can be replayed long after it was sent.
      code: 60 * 60 * 24 * 30,

Summary: 2 critical, 6 high, 1 medium, 4 low, 0 info
Exit code: 1
```

A full finding (without `--brief`): the fix is written for the provider (Stripe) and the
framework (Next.js App Router: `req.text()`, `constructEventAsync`, `new Response(..., 400)`):

```text
webhook-check 0.1.1
Scanned demo-webhooks/web/app/api/webhooks/stripe/route.ts
1 source file(s), 1 webhook handler(s) (Stripe 1)

CRITICAL WHK001  Webhook handler does not verify the signature
      at: demo-webhooks/web/app/api/webhooks/stripe/route.ts:8
      POST /api/webhooks/stripe handles Stripe webhook events (e.g. 'checkout.session.completed')
      but never verifies the signature in Stripe-Signature: anyone who can reach this URL can send
      a forged event; a forged 'checkout.session.completed' / 'invoice.paid' marks an order or
      subscription paid.
      code: export async function POST(req: Request) {
      why: A webhook URL is public: anyone who finds it (it is in your code, your logs, your
           frontend bundle or simply guessable, like /api/webhooks/stripe) can POST to it.
           If the handler acts on the body without checking the provider's signature, a
           forged "checkout.session.completed" or "payment.captured" event unlocks a paid
           plan for free, and a forged "user.deleted" deletes a real account.
      fix:
        1. Read the raw body (the exact bytes Stripe signed):

             const rawBody = await req.text();   // not req.json(): keep the exact bytes

        2. Verify the signature in Stripe-Signature and reject on failure:

             let event;
             try {
               event = await stripe.webhooks.constructEventAsync(rawBody, req.headers.get("stripe-signature"), process.env.STRIPE_WEBHOOK_SECRET);
             } catch (err) {
               return new Response("Invalid signature", { status: 400 });
             }

        3. Only then parse the JSON and act on the event. Keep the secret in an environment
           variable, never in code.

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: demo-webhooks/web/app/api/webhooks/stripe/route.ts:8
      POST /api/webhooks/stripe changes state for Stripe events but never records the event id
      (event.id): retries, dashboard re-sends and replays apply the same event twice.
      code: export async function POST(req: Request) {
      why: Providers deliver at least once: retries after a timeout, manual "resend" from
           the dashboard and replays of a captured request all deliver the same event again.
           A handler that changes state without remembering which event ids it has processed
           can credit an account twice, send duplicate emails or re-provision a
           subscription.
      fix:
        Record the event id (event.id) with a unique constraint before acting, and skip repeats:

          // create table processed_webhook_events (id text primary key, received_at timestamptz default now());
          const { rowCount } = await db.query(
            "insert into processed_webhook_events (id) values ($1) on conflict do nothing", [eventId]);
          if (rowCount === 0) return /* 200: already handled */;

        Do the insert in the same transaction as the state change, so a crash cannot record the
        event without applying it.

Summary: 1 critical, 0 high, 0 medium, 1 low, 0 info
Exit code: 1
```

<details>
<summary>The whole demo project: <code>webhook-check scan demo-webhooks --brief</code></summary>

```text
webhook-check 0.1.1
Scanned demo-webhooks
9 source file(s), 14 webhook handler(s) (Stripe 4, Razorpay 3, GitHub 2, Clerk/Svix 1, Lemon Squeezy 1, Paddle 1, Shopify 1, Twilio 1), 2 Razorpay payment-verification endpoint(s)

CRITICAL WHK001  Webhook handler does not verify the signature
      at: api/django_views.py:15
      stripe_webhook() handles Stripe webhook events (e.g. 'checkout.session.completed') but never
      verifies the signature in Stripe-Signature: anyone who can reach this URL can send a forged
      event; a forged 'checkout.session.completed' / 'invoice.paid' marks an order or subscription
      paid.
      code: def stripe_webhook(request):

CRITICAL WHK001  Webhook handler does not verify the signature
      at: api/fastapi_app.py:26
      POST /webhooks/paddle handles Paddle webhook events (e.g. 'transaction.completed') but never
      verifies the signature in Paddle-Signature: anyone who can reach this URL can send a forged
      event; a forged 'transaction.completed' / 'subscription.activated' grants a paid plan.
      code: @app.post("/webhooks/paddle")

CRITICAL WHK001  Webhook handler does not verify the signature
      at: web/app/api/webhooks/stripe/route.ts:8
      POST /api/webhooks/stripe handles Stripe webhook events (e.g. 'checkout.session.completed')
      but never verifies the signature in Stripe-Signature: anyone who can reach this URL can send
      a forged event; a forged 'checkout.session.completed' / 'invoice.paid' marks an order or
      subscription paid.
      code: export async function POST(req: Request) {

CRITICAL WHK001  Webhook handler does not verify the signature
      at: web/server/express.ts:61
      POST /webhooks/shopify/orders-create handles Shopify webhook events but never verifies the
      signature in X-Shopify-Hmac-Sha256: anyone who can reach this URL can send a forged event; a
      forged 'orders/paid' / 'app/uninstalled' event changes orders or deletes shop data.
      code: app.post("/webhooks/shopify/orders-create", async (req, res) => {

CRITICAL WHK001  Webhook handler does not verify the signature
      at: web/server/hono.ts:7
      POST /webhooks/lemonsqueezy handles Lemon Squeezy webhook events (e.g. 'order_created') but
      never verifies the signature in X-Signature: anyone who can reach this URL can send a forged
      event; a forged 'order_created' / 'subscription_created' grants a paid plan.
      code: app.post("/webhooks/lemonsqueezy", async (c) => {

CRITICAL WHK004  Hard-coded webhook signing secret
      at: api/settings.py:7
      Stripe/Svix webhook signing secret (whsec_) hard-coded in STRIPE_WEBHOOK_SECRET: anyone with
      the source can sign forged events. Value: whse**** (39 chars).
      code: STRIPE_WEBHOOK_SECRET = "whse**** (39 chars)"

CRITICAL WHK006  Razorpay payment trusted without verifying razorpay_signature
      at: api/flask_app.py:30
      POST /payment/success reads razorpay_payment_id from the client (Razorpay Checkout callback)
      and never verifies razorpay_signature = HMAC-SHA256(order_id + "|" + payment_id,
      key_secret): anyone can post a made-up or reused payment id and get the order marked paid.
      code: payment_id = request.form["razorpay_payment_id"]

CRITICAL WHK006  Razorpay payment trusted without verifying razorpay_signature
      at: web/server/express.ts:55
      POST /api/payment/verify reads razorpay_payment_id from the client (Razorpay Checkout
      callback) and never verifies razorpay_signature = HMAC-SHA256(order_id + "|" + payment_id,
      key_secret): anyone can post a made-up or reused payment id and get the order marked paid.
      code: const { razorpay_order_id, razorpay_payment_id } = req.body;

HIGH     WHK001  Webhook handler does not verify the signature
      at: api/django_views.py:24
      sms_reply() handles Twilio webhook events but never verifies the signature in X-Twilio-
      Signature: anyone who can reach this URL can send a forged event; forged inbound messages or
      calls trigger replies (billed to you) and actions.
      code: def sms_reply(request):

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: api/fastapi_app.py:18
      Stripe signature is checked in stripe.Webhook.construct_event() against json.dumps(...) (re-
      serialized JSON), not the raw bytes that were signed: key order, spacing and unicode escapes
      differ, so real events fail and the check tends to get disabled.
      code: event = stripe.Webhook.construct_event(json.dumps(data), sig, os.environ["STRIPE_WEBHOOK_SECRET"], tolerance=None)

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: api/flask_app.py:41
      Razorpay signature is checked in client.utility.verify_webhook_signature() against
      json.dumps(...) (re-serialized JSON), not the raw bytes that were signed: key order, spacing
      and unicode escapes differ, so real events fail and the check tends to get disabled.
      code: client.utility.verify_webhook_signature(

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: web/app/api/webhooks/clerk/route.ts:15
      Clerk/Svix signature is checked in wh.verify() against JSON.stringify(...) (re-serialized
      JSON), not the raw bytes that were signed: key order, spacing and unicode escapes differ, so
      real events fail and the check tends to get disabled.
      code: evt = wh.verify(body, {

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: web/pages/api/razorpay/webhook.ts:10
      Razorpay signature is checked in crypto.createHmac().update() against JSON.stringify(...)
      (re-serialized JSON), not the raw bytes that were signed: key order, spacing and unicode
      escapes differ, so real events fail and the check tends to get disabled.
      JSON.stringify(req.body) is a widely copied Razorpay pattern; it only works while Razorpay's
      serialisation happens to match JSON.stringify's.
      code: .update(JSON.stringify(req.body))

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: web/server/express.ts:17
      GitHub signature is checked in crypto.createHmac().update() against JSON.stringify(...) (re-
      serialized JSON), not the raw bytes that were signed: key order, spacing and unicode escapes
      differ, so real events fail and the check tends to get disabled.
      code: const digest = "sha256=" + crypto.createHmac("sha256", GITHUB_WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest("hex");

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: web/server/express.ts:28
      Stripe signature is checked in stripe.webhooks.constructEvent() against req.body, but
      express.json() is registered first (line 10), so req.body is a parsed object here; a route-
      level express.raw() cannot undo that.
      code: event = stripe.webhooks.constructEvent(

HIGH     WHK002  Signature checked against parsed / re-serialized JSON
      at: web/server/express.ts:46
      Razorpay signature is checked in validateWebhookSignature() against JSON.stringify(...) (re-
      serialized JSON), not the raw bytes that were signed: key order, spacing and unicode escapes
      differ, so real events fail and the check tends to get disabled. JSON.stringify(req.body) is
      a widely copied Razorpay pattern; it only works while Razorpay's serialisation happens to
      match JSON.stringify's.
      code: validateWebhookSignature(JSON.stringify(req.body), req.headers["x-razorpay-signature"] as string, process.env.RAZORPAY_WEBHOOK_SECRET as string);

HIGH     WHK004  Hard-coded webhook signing secret
      at: api/flask_app.py:14
      Webhook signing secret hard-coded as the default for GITHUB_WEBHOOK_SECRET: anyone with the
      source can sign forged events. Value: dev-**** (23 chars).
      code: GITHUB_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "dev-**** (23 chars)")

HIGH     WHK004  Hard-coded webhook signing secret
      at: web/server/express.ts:12
      Webhook signing secret hard-coded in GITHUB_WEBHOOK_SECRET: anyone with the source can sign
      forged events. Value: gh-h**** (24 chars).
      code: const GITHUB_WEBHOOK_SECRET = "gh-h**** (24 chars)";

HIGH     WHK005  Signature verification failure is ignored
      at: api/flask_app.py:44
      Signature verification failure (client.utility.verify_webhook_signature) is caught and the
      handler carries on: this except block neither returns nor raises, so a forged event is
      processed anyway.
      code: except razorpay.errors.SignatureVerificationError:

HIGH     WHK005  Signature verification failure is ignored
      at: web/app/api/webhooks/clerk/route.ts:20
      Signature verification failure is caught and the handler carries on: this catch block
      neither returns nor throws, so a forged event is processed anyway.
      code: } catch (err) {

HIGH     WHK005  Signature verification failure is ignored
      at: web/server/express.ts:34
      Signature verification failure is caught and the handler carries on: this catch block
      neither returns nor throws, and it falls back to the unverified body, so a forged event is
      processed anyway.
      code: } catch (err) {

HIGH     WHK005  Signature verification failure is ignored
      at: web/server/express.ts:46
      The result of validateWebhookSignature() is ignored: it returns false for a bad signature
      instead of throwing, so this line verifies nothing.
      code: validateWebhookSignature(JSON.stringify(req.body), req.headers["x-razorpay-signature"] as string, process.env.RAZORPAY_WEBHOOK_SECRET as string);

MEDIUM   WHK003  Signature compared with == instead of a constant-time comparison
      at: api/flask_app.py:21
      HMAC signature `expected` is compared with '!=': a non-constant-time comparison leaks how
      much of a forged signature is right (timing attack).
      code: if signature != expected:

MEDIUM   WHK003  Signature compared with == instead of a constant-time comparison
      at: web/pages/api/razorpay/webhook.ts:13
      HMAC signature `expected` is compared with '!==': a non-constant-time comparison leaks how
      much of a forged signature is right (timing attack).
      code: if (expected !== signature) {

MEDIUM   WHK003  Signature compared with == instead of a constant-time comparison
      at: web/server/express.ts:18
      HMAC signature `digest` is compared with '===': a non-constant-time comparison leaks how
      much of a forged signature is right (timing attack).
      code: if (sig === digest && req.get("x-github-event") === "push") {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: api/django_views.py:15
      stripe_webhook() changes state for Stripe events but never records the event id (event.id):
      retries, dashboard re-sends and replays apply the same event twice.
      code: def stripe_webhook(request):

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: api/fastapi_app.py:13
      POST /webhooks/stripe changes state for Stripe events but never records the event id
      (event.id): retries, dashboard re-sends and replays apply the same event twice.
      code: @app.post("/webhooks/stripe")

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: api/fastapi_app.py:26
      POST /webhooks/paddle changes state for Paddle events but never records the event id
      (event_id in the body): retries, dashboard re-sends and replays apply the same event twice.
      code: @app.post("/webhooks/paddle")

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: api/flask_app.py:37
      POST /webhooks/razorpay changes state for Razorpay events but never records the event id
      (the X-Razorpay-Event-Id header): retries, dashboard re-sends and replays apply the same
      event twice.
      code: @app.post("/webhooks/razorpay")

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: web/app/api/webhooks/stripe/route.ts:8
      POST /api/webhooks/stripe changes state for Stripe events but never records the event id
      (event.id): retries, dashboard re-sends and replays apply the same event twice.
      code: export async function POST(req: Request) {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: web/pages/api/razorpay/webhook.ts:6
      POST /api/razorpay/webhook changes state for Razorpay events but never records the event id
      (the X-Razorpay-Event-Id header): retries, dashboard re-sends and replays apply the same
      event twice.
      code: export default async function handler(req: NextApiRequest, res: NextApiResponse) {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: web/server/express.ts:25
      POST /webhooks/stripe changes state for Stripe events but never records the event id
      (event.id): retries, dashboard re-sends and replays apply the same event twice.
      code: app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: web/server/express.ts:45
      POST /webhooks/razorpay changes state for Razorpay events but never records the event id
      (the X-Razorpay-Event-Id header): retries, dashboard re-sends and replays apply the same
      event twice.
      code: app.post("/webhooks/razorpay", async (req, res) => {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: web/server/express.ts:61
      POST /webhooks/shopify/orders-create changes state for Shopify events but never records the
      event id (the X-Shopify-Webhook-Id header): retries, dashboard re-sends and replays apply
      the same event twice.
      code: app.post("/webhooks/shopify/orders-create", async (req, res) => {

LOW      WHK007  Webhook events are not de-duplicated [heuristic]
      at: web/server/hono.ts:7
      POST /webhooks/lemonsqueezy changes state for Lemon Squeezy events but never records the
      event id (data.id + meta.event_name; Lemon Squeezy sends no delivery id): retries, dashboard
      re-sends and replays apply the same event twice.
      code: app.post("/webhooks/lemonsqueezy", async (c) => {

LOW      WHK008  Stripe signature tolerance disabled or very large
      at: api/fastapi_app.py:18
      Stripe signature tolerance is None (timestamp check disabled): a captured event (from logs
      or a proxy) can be replayed long after it was sent.
      code: event = stripe.Webhook.construct_event(json.dumps(data), sig, os.environ["STRIPE_WEBHOOK_SECRET"], tolerance=None)

LOW      WHK008  Stripe signature tolerance disabled or very large
      at: web/server/express.ts:32
      Stripe signature tolerance is 60 * 60 * 24 * 30 = 2592000 seconds instead of the default
      300: a captured event (from logs or a proxy) can be replayed long after it was sent.
      code: 60 * 60 * 24 * 30,

Summary: 8 critical, 14 high, 3 medium, 12 low, 0 info
Exit code: 1
```

</details>

The same handlers written correctly (`tests/fixtures/node_clean`, `tests/fixtures/py_clean`)
produce no findings, and every handler is recognised as verified:

```text
webhook-check 0.1.1
Scanned tests/fixtures/node_clean, tests/fixtures/py_clean
8 source file(s), 14 webhook handler(s) (Stripe 4, Clerk/Svix 2, GitHub 2, Razorpay 2, Lemon Squeezy 1, Paddle 1, Shopify 1, Twilio 1), 2 Razorpay payment-verification endpoint(s)

No findings. (This is not a guarantee: see 'What it does not check' in the README.)
Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info
Exit code: 0
```

## What it checks

| Rule | Severity | What it finds |
|---|---|---|
| WHK001 | Critical (Twilio: High) | A handler that processes a provider's events and never verifies its signature. Recognised verification: Stripe `stripe.webhooks.constructEvent` / `constructEventAsync`, `stripe.Webhook.construct_event`, `WebhookSignature.verify_header`; Razorpay `validateWebhookSignature`, `client.utility.verify_webhook_signature`; Svix `new Webhook(secret).verify(...)`, Clerk `verifyWebhook(req)`; Shopify `shopify.webhooks.validate`, `authenticate.webhook`; Paddle `webhooks.unmarshal`, `Verifier().verify`; Twilio `validateRequest`, `twilio.webhook()`, `RequestValidator`; PayPal `verify-webhook-signature`; `@octokit/webhooks` `verify`; any HMAC (`createHmac`, `hmac.new`, `crypto.subtle`), `timingSafeEqual` / `compare_digest`, a helper or middleware named like `verifySignature` / `validate_webhook`, or a `verify*(req)` call. |
| WHK002 | High | The signature is verified against re-serialized or parsed JSON: `JSON.stringify(...)`, `json.dumps(...)`, a variable from `await req.json()`, `request.get_json()`, `request.json`, `json.loads(...)`, `JSON.parse(...)` (followed through local variables); `req.body` in Next.js `pages/api` without `bodyParser: false`; `req.body` in Express when `app.use(express.json())` is registered before the route (a route-level `express.raw()` does not help then); `request.body` in Fastify without a raw-body content-type parser. |
| WHK003 | Medium | An HMAC digest (a variable assigned from `createHmac(...).digest()`, `hmac.new(...).hexdigest()`, `base64.b64encode(hmac...)`, or an inline digest) compared with `==`, `===`, `!=`, `!==`. Length checks, comparisons with `null` / `""` and plain (non-HMAC) hashes are not reported. |
| WHK004 | Critical / High | A `whsec_...` (Stripe / Svix) secret in code is Critical. A string literal assigned to a webhook-secret name (`STRIPE_WEBHOOK_SECRET`, `webhookSecret`, `signing_secret`, `RAZORPAY_KEY_SECRET`, `TWILIO_AUTH_TOKEN`, ...), used as the fallback of `process.env.X \|\| "..."` / `os.environ.get("X", "...")`, or passed directly as the secret of a verification call (`constructEvent`, `createHmac`, `hmac.new`, `new Webhook`, `RequestValidator`, ...) is High. Placeholders (`your-secret`, `whsec_...`, `xxxx`) and env-var names are ignored. |
| WHK005 | High | Verification inside `try` whose `catch` / `except` neither returns nor throws (and especially one that falls back to the unverified body), or a boolean check used as a bare statement: `validateWebhookSignature(...)`, `timingSafeEqual(...)`, `hmac.compare_digest(...)`. `catch { event = null }` followed by `if (!event) return` is understood. |
| WHK006 | Critical | A route that reads `razorpay_payment_id` from the request (the Razorpay Checkout callback) and never checks `razorpay_signature`: no `validatePaymentVerification`, `verify_payment_signature`, HMAC, or server-side `payments.fetch`. |
| WHK007 | Low (heuristic) | A provider webhook handler that writes to a database / grants access (`db.order.update(...)`, `markPaid(...)` or `db.markPaid(...)`, the same in every framework) but never references an event or delivery id (`event.id`, `X-GitHub-Delivery`, `svix-id`, `X-Razorpay-Event-Id`, `X-Shopify-Webhook-Id`, ...), an idempotency key, an upsert or `on conflict`. |
| WHK008 | Low | Stripe `constructEvent(..., tolerance)` / `construct_event(..., tolerance=...)` set to `0` / `None` / negative (timestamp check disabled) or above 600 seconds. |

**How handlers are found.** Next.js `export async function POST` in `app/**/route.ts` and
default exports in `pages/api/**`; `app.post("/path", ...)` / `router.post` / `.route("/path").post`
(Express, Hono, Fastify, Koa routers), Fastify `route({ method: "POST" })`, NestJS `@Post()`,
`Deno.serve(...)`; Python `@app.post`, `@router.post`, `@app.route(..., methods=["POST"])`,
`api_route`, `add_url_rule` / `add_api_route`, Django views marked `@csrf_exempt` /
`@require_POST` / `@api_view(["POST"])` and class-based `post()` methods. Any other function
that reads the request and carries strong provider evidence (signature / event headers,
verification calls, or event types plus the provider SDK) is also checked, which covers
controllers in their own file and Lambda / Workers handlers. Same-file helper functions
called from a handler are followed two levels deep.

A route is only treated as a webhook when the provider is clear: a provider header or
verification call, event types such as `checkout.session.completed` together with the
provider's SDK or the provider's name in the route path, a path like `/webhooks/stripe`, or a
webhook path (`/api/webhooks`) whose body checks only one provider's event types. None of these
needs the provider's SDK to be imported: `app/api/webhooks/stripe/route.ts` that reads
`event.type` from `await req.json()` is found from its path alone. `POST /api/stripe/checkout`
(creating a session) is not a webhook and is not reported.

| Provider | Signature header | Scheme the fix uses |
|---|---|---|
| Stripe | `Stripe-Signature` | `constructEvent(rawBody, sig, secret)` / `stripe.Webhook.construct_event(payload, sig, secret)` |
| Razorpay | `X-Razorpay-Signature` | hex HMAC-SHA256 of the raw body with the webhook secret; Python `client.utility.verify_webhook_signature` |
| GitHub | `X-Hub-Signature-256` | `"sha256=" + hex HMAC-SHA256(raw body, secret)` |
| Clerk / Svix | `svix-id`, `svix-timestamp`, `svix-signature` | `new Webhook(secret).verify(rawBody, headers)`; Clerk `verifyWebhook(req)` |
| Shopify | `X-Shopify-Hmac-Sha256` | base64 HMAC-SHA256 of the raw body with the app's client secret |
| Paddle (Billing) | `Paddle-Signature` (`ts=...;h1=...`) | hex HMAC-SHA256 of `ts + ":" + raw body`, plus a timestamp check |
| Lemon Squeezy | `X-Signature` | hex HMAC-SHA256 of the raw body with the signing secret |
| Twilio | `X-Twilio-Signature` | `twilio.validateRequest(token, sig, url, params)` / `RequestValidator.validate` |
| PayPal | `PAYPAL-TRANSMISSION-SIG` and the other `PAYPAL-*` headers | `POST /v1/notifications/verify-webhook-signature`, `verification_status == "SUCCESS"` |

`node_modules`, `.git`, virtualenvs, build output (`.next`, `dist`, ...), Django migrations and
test / fixture / mock folders and files are skipped (use `--include-tests` to scan tests,
`--exclude GLOB` to skip more).

## What it does not check

Be clear about the limits before relying on it:

- **It is not a penetration test** and gives **no guarantee**. A clean report means "none of
  these known patterns were found", nothing more.
- **No cross-file analysis.** Verification done in another module, a Next.js `middleware.ts`,
  or an Express app file that mounts the router is not seen. To avoid false alarms, a handler
  that hands the request to a function from another file, or that sits behind middleware /
  decorators it does not recognise, is **not** reported as unverified (`signature_verified: null`
  in the JSON). The `express.json()`-before-route check only works when both are in one file.
- **Verification is recognised by name and pattern, not proven correct.** An HMAC over the
  wrong data, with the wrong secret or header, still counts as "verified"; so does any helper
  named like `verifySignature` or any `verify*(req)` call.
- **TypeScript/JavaScript is analysed without a full parser** (comments and strings are lexed
  out, then patterns are matched). Unusual code shapes, handlers built by factories, or routes
  registered from config may be missed. Python uses the real `ast` module and is more precise.
- **Providers not covered:** Supabase database webhooks (they carry whatever headers you
  configure, so there is no standard signature to look for), Paddle Classic (`p_signature`),
  and providers not listed above. Custom in-house webhooks are not checked for WHK001. GitHub's
  legacy SHA-1 `X-Hub-Signature` is accepted without a separate warning.
- **WHK006 is Razorpay-only.** Fetching the payment from Razorpay's API counts as verification
  even if the code then fails to compare the order id or amount. Trusting a Stripe `session_id`
  on a success page is not checked.
- **WHK007 is a heuristic**: any reference to an event id, an upsert or `get_or_create` counts
  as de-duplication.
- **WHK004 looks at code only** (`.py`, `.js`, `.ts`, ...), not `.env` files, and only at
  `whsec_` values, webhook-secret names and literals passed to verification calls.
- Other languages (Go, Ruby, PHP, Java, C#) and other frameworks (SvelteKit, Remix, Nuxt route
  files are only found through the generic "function that reads the request" path) are not
  supported yet.

## How to fix each finding

`webhook-check rules` prints all of this. Every finding in a report carries its own fix with
the provider, framework, route and variable names filled in.

**WHK001 - no verification.** Read the raw body, verify the provider's signature, return 400 on
failure, and only then parse the JSON:

```ts
// Next.js App Router
const rawBody = await req.text();
let event;
try {
  event = await stripe.webhooks.constructEventAsync(rawBody, req.headers.get("stripe-signature"), process.env.STRIPE_WEBHOOK_SECRET);
} catch {
  return new Response("Invalid signature", { status: 400 });
}
```
```python
# Django
try:
    event = stripe.Webhook.construct_event(request.body, request.headers.get("Stripe-Signature", ""),
                                           os.environ["STRIPE_WEBHOOK_SECRET"])
except (ValueError, stripe.error.SignatureVerificationError):
    return HttpResponse(status=400)
```

**WHK002 - parsed body.** Next.js App Router / Hono / Deno: `await req.text()`. Next.js
`pages/api`: `export const config = { api: { bodyParser: false } }` and read the stream.
Express: `app.post(path, express.raw({ type: "application/json" }), handler)` registered
**before** `app.use(express.json())`. Fastify: a `parseAs: "buffer"` content-type parser.
FastAPI: `await request.body()`. Flask: `request.get_data()`. Django: `request.body`.

**WHK003 - `==` on signatures.** `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` after
a length check; `hmac.compare_digest(a, b)` in Python.

**WHK004 - hard-coded secret.** Roll it in the provider's dashboard, read it from the
environment with no fallback, and scrub it from git history.

**WHK005 - failure ignored.** `return` / `throw` / `raise` in the catch / except block; use the
boolean result of `validateWebhookSignature`, `timingSafeEqual`, `compare_digest`.

**WHK006 - Razorpay callback.** Check `razorpay_signature` against
HMAC-SHA256(`<order id you stored>|<razorpay_payment_id>`, key secret)
(`validatePaymentVerification` / `client.utility.verify_payment_signature`), then take the
amount from your own order record, and treat the `payment.captured` webhook as the source of
truth.

**WHK007 - no de-duplication.** Insert the event id into a table with a unique constraint
(`on conflict do nothing`) in the same transaction as the state change; skip if it was
already there.

**WHK008 - tolerance.** Drop the argument and keep Stripe's 300-second default.

## Suppressing a finding

Add `webhook-check: ignore` as a comment on the reported line (works in Python and JS/TS):

```ts
app.post("/webhooks/internal", handler); // webhook-check: ignore  (mTLS-only internal endpoint)
```

To turn a rule off for a whole run: `--disable WHK007` (repeatable). To hide low-severity
findings: `--min-severity medium`.

## Use in CI

See [`examples/github-actions/webhook-check.yml`](examples/github-actions/webhook-check.yml). It
runs on every pull request, fails the build on Critical/High findings, and uploads the JSON
report as an artifact.

## JSON output

`--json` prints (two handlers and one finding shown, from the demo project):

```json
{
  "tool": "webhook-check",
  "version": "0.1.1",
  "targets": [
    "/abs/path/demo-webhooks"
  ],
  "files_scanned": 9,
  "handlers": [
    {
      "file": "api/django_views.py",
      "line": 15,
      "handler": "stripe_webhook()",
      "framework": "django",
      "provider": "Stripe",
      "kind": "webhook",
      "signature_verified": false
    },
    {
      "file": "api/django_views.py",
      "line": 24,
      "handler": "sms_reply()",
      "framework": "django",
      "provider": "Twilio",
      "kind": "webhook",
      "signature_verified": false
    }
  ],
  "exit_code": 1,
  "summary": {
    "critical": 8,
    "high": 14,
    "medium": 3,
    "low": 12,
    "info": 0
  },
  "findings": [
    {
      "rule_id": "WHK001",
      "severity": "critical",
      "message": "stripe_webhook() handles Stripe webhook events (e.g. 'checkout.session.completed') but never verifies the signature in Stripe-Signature: anyone who can reach this URL can send a forged event; a forged 'checkout.session.completed' / 'invoice.paid' marks an order or subscription paid.",
      "file": "api/django_views.py",
      "line": 15,
      "evidence": "def stripe_webhook(request):",
      "heuristic": false,
      "extra": {
        "lang": "py",
        "framework": "django",
        "provider": "stripe",
        "route": "stripe_webhook"
      },
      "title": "Webhook handler does not verify the signature",
      "why": "A webhook URL is public: anyone who finds it (it is in your code, your logs, your frontend bundle or simply guessable, like /api/webhooks/stripe) can POST to it. If the handler acts on the body without checking the provider's signature, a forged \"checkout.session.completed\" or \"payment.captured\" event unlocks a paid plan for free, and a forged \"user.deleted\" deletes a real account.",
      "fix": "1. Read the raw body (the exact bytes Stripe signed):\n\n     payload = request.body\n\n2. Verify the signature in Stripe-Signature and reject on failure:\n\n     import stripe\n     try:\n         event = stripe.Webhook.construct_event(\n             payload, request.headers.get(\"Stripe-Signature\", \"\"), os.environ[\"STRIPE_WEBHOOK_SECRET\"])\n     except (ValueError, stripe.error.SignatureVerificationError):\n         return HttpResponse(status=400)\n\n3. Only then parse the JSON and act on the event. Keep the secret in an environment\n   variable, never in code."
    }
  ]
}
```

`signature_verified` is `true`, `false`, or `null` when the handler sits behind middleware or
decorators the tool cannot see into.

## Development

```bash
pip install -e ".[test]"
pytest
```

Test fixtures never contain real or real-looking secrets in the repository: fake keys are
assembled at runtime in `tests/conftest.py` and `examples/make_demo.py`. Every rule has tests
for code that must be reported and for correctly verified code that must not be.

## License

MIT, Copyright (c) 2026 Abheesht Tripathi. See [LICENSE](LICENSE).

---

Questions, or want a review of your payment and webhook handling before you launch? abheeshttripathi890@gmail.com
