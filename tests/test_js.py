"""Node / TypeScript handlers: true positives and correctly verified handlers that must stay quiet."""

from pathlib import Path

import pytest

from conftest import js, rules
from webhook_check.scanner import scan_path

FIX = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- fixtures
def test_vulnerable_fixture_exact_findings():
    res = scan_path(str(FIX / "node_vulnerable"))
    got = sorted((f.rule_id, f.file, f.line, f.severity) for f in res.findings)
    assert got == sorted([
        ("WHK001", "app/api/webhooks/stripe/route.ts", 8, "critical"),
        ("WHK007", "app/api/webhooks/stripe/route.ts", 8, "low"),
        ("WHK002", "app/api/webhooks/clerk/route.ts", 15, "high"),
        ("WHK005", "app/api/webhooks/clerk/route.ts", 20, "high"),
        ("WHK002", "pages/api/razorpay/webhook.ts", 10, "high"),
        ("WHK003", "pages/api/razorpay/webhook.ts", 13, "medium"),
        ("WHK007", "pages/api/razorpay/webhook.ts", 6, "low"),
        ("WHK004", "server/express.ts", 12, "high"),
        ("WHK002", "server/express.ts", 17, "high"),
        ("WHK003", "server/express.ts", 18, "medium"),
        ("WHK002", "server/express.ts", 28, "high"),
        ("WHK008", "server/express.ts", 32, "low"),
        ("WHK005", "server/express.ts", 34, "high"),
        ("WHK007", "server/express.ts", 25, "low"),
        ("WHK002", "server/express.ts", 46, "high"),
        ("WHK005", "server/express.ts", 46, "high"),
        ("WHK007", "server/express.ts", 45, "low"),
        ("WHK006", "server/express.ts", 55, "critical"),
        ("WHK001", "server/express.ts", 61, "critical"),
        ("WHK007", "server/express.ts", 61, "low"),
        ("WHK001", "server/hono.ts", 7, "critical"),
        ("WHK007", "server/hono.ts", 7, "low"),
    ])


def test_clean_fixture_no_findings_and_all_handlers_verified():
    res = scan_path(str(FIX / "node_clean"))
    assert res.findings == []
    assert len(res.handlers) == 8
    assert all(h.verified is True for h in res.handlers)
    labels = {h.label for h in res.handlers}
    assert "POST /api/stripe/checkout" not in labels     # creating a checkout session is not a webhook


def test_frameworks_detected():
    res = scan_path(str(FIX / "node_vulnerable"))
    fw = {h.label: h.framework for h in res.handlers}
    assert fw["POST /api/webhooks/stripe"] == "next-app"
    assert fw["POST /api/razorpay/webhook"] == "next-pages"
    assert fw["POST /webhooks/github"] == "express"
    assert fw["POST /webhooks/lemonsqueezy"] == "hono"


# ---------------------------------------------------------------- WHK001 per provider
UNVERIFIED = {
    "stripe": ('app.post("/stripe/webhook", async (req, res) => {\n'
               '  const event = req.body;\n  if (event.type === "invoice.paid") await activate(event.data.object.customer);\n'
               '  res.json({ ok: true });\n});\n', "critical"),
    "github": ('app.post("/hooks/gh", (req, res) => {\n'
               '  if (req.headers["x-github-event"] === "push") deploy(req.body.ref);\n  res.end();\n});\n', "critical"),
    "svix": ('app.post("/api/clerk-webhook", async (req, res) => {\n'
             '  const id = req.headers["svix-id"];\n  await syncUser(req.body.data);\n  res.end();\n});\n', "critical"),
    "paddle": ('app.post("/paddle/webhook", async (req, res) => {\n'
               '  if (req.body.event_type === "subscription.activated") await grant(req.body.data.customer_id);\n'
               '  res.end();\n});\n', "critical"),
    "paypal": ('app.post("/paypal/webhook", async (req, res) => {\n'
               '  if (req.body.event_type === "PAYMENT.CAPTURE.COMPLETED") await markPaid(req.body.resource.id);\n'
               '  res.end();\n});\n', "critical"),
    "twilio": ('import twilio from "twilio";\napp.post("/sms", (req, res) => {\n'
               '  const twiml = new twilio.twiml.MessagingResponse();\n  twiml.message(reply(req.body.Body));\n'
               '  res.type("text/xml").send(twiml.toString());\n});\n', "high"),
}


@pytest.mark.parametrize("provider", sorted(UNVERIFIED))
def test_unverified_handler_per_provider(provider):
    body, sev = UNVERIFIED[provider]
    src = 'import express from "express";\nconst app = express();\n' + body
    findings, handlers = js(src)
    assert [h.provider for h in handlers] == [provider]
    w1 = [f for f in findings if f.rule_id == "WHK001"]
    assert len(w1) == 1 and w1[0].severity == sev
    assert w1[0].extra["provider"] == provider


VERIFIED = {
    "paypal": ('app.post("/paypal/webhook", async (req, res) => {\n'
               '  const r = await fetch("https://api-m.paypal.com/v1/notifications/verify-webhook-signature", {\n'
               '    method: "POST", body: JSON.stringify({ transmission_sig: req.headers["paypal-transmission-sig"] }) });\n'
               '  if ((await r.json()).verification_status !== "SUCCESS") return res.sendStatus(400);\n'
               '  if (req.body.event_type === "PAYMENT.CAPTURE.COMPLETED") await markPaid(req.body.id);\n'
               '  res.end();\n});\n'),
    "twilio-middleware": ('import twilio from "twilio";\napp.post("/sms", twilio.webhook(), (req, res) => {\n'
                          '  const twiml = new twilio.twiml.MessagingResponse();\n  twiml.message("hi " + req.body.From);\n'
                          '  res.send(twiml.toString());\n});\n'),
    "twilio-validate": ('import twilio from "twilio";\napp.post("/sms", (req, res) => {\n'
                        '  const ok = twilio.validateRequest(process.env.TWILIO_AUTH_TOKEN, req.headers["x-twilio-signature"], url, req.body);\n'
                        '  if (!ok) return res.sendStatus(403);\n  const twiml = new twilio.twiml.MessagingResponse();\n'
                        '  res.send(twiml.toString());\n});\n'),
    "verify-middleware": ('app.post("/webhooks/github", express.raw({ type: "*/*" }), verifyGithubSignature, (req, res) => {\n'
                          '  if (req.headers["x-github-event"] === "push") deploy(req.body);\n  res.end();\n});\n'),
    "helper": ('function checkSignature(req) {\n  const d = crypto.createHmac("sha256", s).update(req.body).digest("hex");\n'
               '  return crypto.timingSafeEqual(Buffer.from(d), Buffer.from(String(req.headers["x-signature"])));\n}\n'
               'app.post("/webhooks/lemonsqueezy", express.raw({ type: "*/*" }), (req, res) => {\n'
               '  if (!checkSignature(req)) return res.sendStatus(400);\n'
               '  if (req.headers["x-event-name"] === "order_created") grantAccess(JSON.parse(req.body).data.id);\n'
               '  res.end();\n});\n'),
    "app-level-use": ('app.use("/webhooks", verifyWebhookSignature);\n'
                      'app.post("/webhooks/stripe", (req, res) => {\n  if (req.body.type === "invoice.paid") activate(req.body.id);\n'
                      '  res.end();\n});\n'),
}


@pytest.mark.parametrize("case", sorted(VERIFIED))
def test_verified_handlers_not_reported(case):
    src = 'import express from "express";\nimport crypto from "crypto";\nconst app = express();\n' + VERIFIED[case]
    findings, handlers = js(src)
    assert handlers, "handler should still be recognised"
    assert "WHK001" not in rules(findings)


def test_unknown_middleware_makes_handler_opaque_not_reported():
    src = ('import express from "express";\nconst app = express();\n'
           'app.post("/webhooks/stripe", requireStripe, (req, res) => {\n'
           '  if (req.body.type === "checkout.session.completed") fulfil(req.body.data);\n  res.end();\n});\n')
    findings, handlers = js(src)
    assert handlers[0].verified is None
    assert "WHK001" not in rules(findings)


def test_non_webhook_routes_not_reported():
    src = ('import express from "express";\nimport Stripe from "stripe";\nconst app = express();\n'
           'app.post("/api/stripe/checkout", async (req, res) => {\n'
           '  const s = await stripe.checkout.sessions.create({ line_items: req.body.items });\n  res.json(s);\n});\n'
           'app.post("/api/contact", async (req, res) => { await sendMail(req.body); res.end(); });\n'
           'await axios.post("/webhooks/stripe", { type: "invoice.paid" });\n')
    findings, handlers = js(src)
    assert handlers == [] and findings == []


def test_event_dispatch_function_without_request_is_not_a_handler():
    src = ('import Stripe from "stripe";\nexport async function handleEvent(event: Stripe.Event) {\n'
           '  if (event.type === "checkout.session.completed") await db.order.update({});\n}\n')
    findings, handlers = js(src, "lib/stripe-events.ts")
    assert handlers == [] and findings == []


def test_controller_function_in_other_file_is_found():
    src = ('import Stripe from "stripe";\nexport const stripeWebhook = async (req, res) => {\n'
           '  const event = req.body;\n  if (event.type === "invoice.paid") await db.invoice.update({});\n'
           '  res.sendStatus(200);\n};\n')
    findings, handlers = js(src, "controllers/billing.ts")
    assert handlers[0].label == "stripeWebhook()"
    assert "WHK001" in rules(findings)


def test_lambda_handler():
    bad = ('export const handler = async (event) => {\n  const body = JSON.parse(event.body);\n'
           '  if (event.headers["x-github-event"] === "release") await publish(body.release);\n'
           '  return { statusCode: 200 };\n};\n')
    findings, handlers = js(bad, "functions/github.js")
    assert "WHK001" in rules(findings)


def test_nestjs_controller():
    good = ('import { Controller, Post, Req, Headers } from "@nestjs/common";\n@Controller("webhooks")\n'
            'export class StripeController {\n  @Post("stripe")\n'
            '  async handle(@Req() req: RawBodyRequest<Request>, @Headers("stripe-signature") sig: string) {\n'
            '    const event = this.stripe.webhooks.constructEvent(req.rawBody, sig, this.secret);\n'
            '    return { ok: true };\n  }\n}\n')
    findings, handlers = js(good, "src/stripe.controller.ts")
    assert handlers[0].label == "POST /webhooks/stripe" and handlers[0].verified is True
    assert findings == []
    bad = good.replace("req.rawBody", "JSON.stringify(req.body)")
    findings, _ = js(bad, "src/stripe.controller.ts")
    assert rules(findings) == ["WHK002"]


def test_fastify_raw_body():
    bad = ('import Fastify from "fastify";\nconst fastify = Fastify();\n'
           'fastify.post("/webhooks/stripe", async (request, reply) => {\n'
           '  const event = stripe.webhooks.constructEvent(request.body, request.headers["stripe-signature"], secret);\n'
           '  return { ok: true };\n});\n')
    findings, _ = js(bad)
    w = [f for f in findings if f.rule_id == "WHK002"]
    assert len(w) == 1 and w[0].extra["framework"] == "fastify"
    assert "addContentTypeParser" in w[0].fix
    good = bad.replace("const fastify = Fastify();",
                       'const fastify = Fastify();\nfastify.addContentTypeParser("application/json", { parseAs: "buffer" }, (r, b, d) => d(null, b));')
    assert "WHK002" not in rules(js(good)[0])


def test_fastify_route_object():
    src = ('import Fastify from "fastify";\nconst app = Fastify();\n'
           'app.route({ method: "POST", url: "/webhooks/shopify", handler: async (request, reply) => {\n'
           '  await saveOrder(request.headers["x-shopify-topic"], request.body);\n  return "ok";\n} });\n')
    findings, handlers = js(src)
    assert handlers[0].label == "POST /webhooks/shopify"
    assert "WHK001" in rules(findings)


# ---------------------------------------------------------------- WHK002
def test_next_pages_req_body_without_bodyparser_false():
    src = ('import Stripe from "stripe";\nexport default async function handler(req, res) {\n'
           '  const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);\n'
           '  res.json({ ok: true });\n}\n')
    findings, _ = js(src, "pages/api/stripe.ts")
    assert rules(findings) == ["WHK002"]
    assert "bodyParser: false" in findings[0].fix
    fixed = "export const config = { api: { bodyParser: false } };\n" + src.replace("req.body", "await buffer(req)")
    assert js(fixed, "pages/api/stripe.ts")[0] == []


def test_express_json_after_route_or_on_other_path_is_fine():
    route = ('app.post("/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {\n'
             '  const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);\n'
             '  res.end();\n});\n')
    base = 'import express from "express";\nconst app = express();\n'
    assert "WHK002" not in rules(js(base + route + "app.use(express.json());\n")[0])
    assert "WHK002" not in rules(js(base + 'app.use("/api", express.json());\n' + route)[0])
    assert "WHK002" in rules(js(base + "app.use(bodyParser.json());\n" + route)[0])


def test_app_router_req_json_then_verify():
    src = ('export async function POST(req: Request) {\n  const data = await req.json();\n'
           '  const sig = req.headers.get("x-hub-signature-256");\n'
           '  const digest = "sha256=" + crypto.createHmac("sha256", s).update(JSON.stringify(data)).digest("hex");\n'
           '  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(sig))) return new Response(null, { status: 401 });\n'
           '  return Response.json({});\n}\n')
    findings, _ = js(src, "app/api/github/route.ts")
    assert rules(findings) == ["WHK002"]
    assert "await req.text()" in findings[0].fix


def test_raw_text_payload_not_reported():
    src = ('export async function POST(req: Request) {\n  const body = await req.text();\n'
           '  const evt = await stripe.webhooks.constructEventAsync(body, req.headers.get("stripe-signature")!, s);\n'
           '  return Response.json({ id: evt.id });\n}\n')
    assert js(src, "app/api/stripe/webhook/route.ts")[0] == []


def test_paddle_template_payload_traced():
    src = ('export async function POST(req: Request) {\n  const body = await req.json();\n'
           '  const sig = req.headers.get("paddle-signature");\n  const raw = JSON.stringify(body);\n'
           '  const h = crypto.createHmac("sha256", s).update(`${ts}:${raw}`).digest("hex");\n'
           '  if (!crypto.timingSafeEqual(Buffer.from(h), Buffer.from(h1))) return new Response(null, { status: 400 });\n'
           '  return Response.json({});\n}\n')
    assert "WHK002" in rules(js(src, "app/api/paddle/route.ts")[0])


# ---------------------------------------------------------------- WHK003
def test_compare_negatives():
    src = ('const expected = crypto.createHmac("sha256", s).update(raw).digest("hex");\n'
           'if (expected.length !== sig.length) throw new Error("x");\n'
           'if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) throw new Error("x");\n'
           'if (expected === undefined) throw new Error("x");\n'
           'const hash = crypto.createHash("sha256").update(token).digest("hex");\n'
           'if (hash === stored) ok();\n')
    assert "WHK003" not in rules(js(src, "lib/verify.ts")[0])


def test_compare_inline_and_hmac_object():
    inline = 'if (crypto.createHmac("sha256", s).update(raw).digest("base64") == header) ok();\n'
    assert rules(js(inline, "lib/verify.ts")[0]) == ["WHK003"]
    obj = ('const hmac = crypto.createHmac("sha256", s);\nhmac.update(raw);\nconst sig = hmac.digest("hex");\n'
           'if (sig != req.headers["x-signature"]) return;\n')
    assert rules(js(obj, "lib/verify.ts")[0]) == ["WHK003"]


# ---------------------------------------------------------------- WHK004
def test_whsec_literal_is_critical_and_masked(fake):
    src = f'const endpointSecret = "{fake["whsec"]}";\nconst e = stripe.webhooks.constructEvent(raw, sig, endpointSecret);\n'
    findings, _ = js(src)
    w = [f for f in findings if f.rule_id == "WHK004"]
    assert len(w) == 1 and w[0].severity == "critical"
    for text in (w[0].message, w[0].evidence, w[0].fix):
        assert fake["whsec"] not in text and fake["whsec"][:8] not in text


def test_secret_fallback_and_direct_argument(fake):
    src = (f'const s = process.env.GITHUB_WEBHOOK_SECRET || "{fake["generic"]}";\n'
           f'const d = crypto.createHmac("sha256", "{fake["generic"]}x").update(raw).digest("hex");\n'
           f'const wh = new Webhook("{fake["generic"]}y");\n')
    findings, _ = js(src)
    w = [f for f in findings if f.rule_id == "WHK004"]
    assert [f.line for f in w] == [1, 2, 3] and {f.severity for f in w} == {"high"}
    assert all(fake["generic"][:8] not in f.evidence for f in w)


def test_placeholders_and_env_names_not_reported():
    src = ('const STRIPE_WEBHOOK_SECRET = "whsec_...";\nconst webhookSecret = "your-webhook-secret";\n'
           'const signingSecret = process.env.SIGNING_SECRET ?? "";\nconst name = "STRIPE_WEBHOOK_SECRET";\n'
           'const webhookSecret2 = "whsec_xxxxxxxxxxxxxxxxxxxxxxxx";\n// const WEBHOOK_SECRET = "Zq8vN2pLr5Tx9WmK4c";\n')
    assert "WHK004" not in rules(js(src)[0])


# ---------------------------------------------------------------- WHK005
def test_catch_that_rejects_is_fine():
    src = ('let event;\ntry {\n  event = stripe.webhooks.constructEvent(raw, sig, s);\n} catch (err) {\n'
           '  console.error(err);\n  res.status(400).send("bad");\n}\n')
    assert "WHK005" not in rules(js(src)[0])
    nulled = ('let event;\ntry {\n  event = wh.verify(raw, headers);\n} catch (err) {\n  event = null;\n}\n'
              'if (!event) return new Response("bad", { status: 400 });\n')
    assert "WHK005" not in rules(js(nulled)[0])


def test_ignored_boolean_results():
    src = ('crypto.timingSafeEqual(a, b);\nif (!validateWebhookSignature(body, sig, s)) return;\n'
           'const ok = validateWebhookSignature(body, sig, s);\n')
    findings, _ = js(src)
    assert [(f.rule_id, f.line) for f in findings] == [("WHK005", 1)]


# ---------------------------------------------------------------- WHK006
def test_razorpay_payment_verification_variants():
    base = 'import express from "express";\nconst app = express();\napp.post("/api/verify", async (req, res) => {\n%s\n});\n'
    bad = '  const { razorpay_payment_id } = req.body;\n  await Order.updateOne({}, { paid: razorpay_payment_id });\n  res.json({});'
    assert rules(js(base % bad)[0]) == ["WHK006"]
    fetched = ('  const p = await razorpay.payments.fetch(req.body.razorpay_payment_id);\n'
               '  if (p.status === "captured" && p.order_id === order.id) await markPaid(order);\n  res.json({});')
    assert js(base % fetched)[0] == []
    hmac = ('  const { razorpay_order_id: o, razorpay_payment_id: p, razorpay_signature: s } = req.body;\n'
            '  const d = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(order.id + "|" + p).digest("hex");\n'
            '  if (!crypto.timingSafeEqual(Buffer.from(d), Buffer.from(s))) return res.status(400).end();\n  res.json({});')
    assert js(base % hmac)[0] == []


def test_frontend_checkout_handler_not_reported():
    src = ('const rzp = new Razorpay({ key, order_id, handler: async (response) => {\n'
           '  await fetch("/api/verify", { method: "POST", body: JSON.stringify({ razorpay_payment_id: response.razorpay_payment_id }) });\n'
           '} });\n')
    assert js(src, "components/Pay.tsx") == ([], [])


# ---------------------------------------------------------------- WHK007 / WHK008
def test_dedupe_evidence_suppresses_whk007():
    src = ('app.post("/webhooks/stripe", express.raw({ type: "*/*" }), async (req, res) => {\n'
           '  const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], s);\n'
           '  if (await seen(event.id)) return res.end();\n  await db.order.update({});\n  res.end();\n});\n')
    assert js('import express from "express";\nconst app = express();\n' + src)[0] == []


@pytest.mark.parametrize("tol,hit", [("300", False), ("0", True), ("86400", True), ("Infinity", True), ("tol", False)])
def test_tolerance(tol, hit):
    src = f"const e = stripe.webhooks.constructEvent(raw, sig, secret, {tol});\n"
    assert ("WHK008" in rules(js(src)[0])) is hit


def test_inline_ignore(make_repo):
    src = UNVERIFIED["github"][0].replace('app.post("/hooks/gh", (req, res) => {',
                                          'app.post("/hooks/gh", (req, res) => { // webhook-check: ignore')
    root = make_repo({"server.js": 'const app = require("express")();\n' + src})
    assert scan_path(str(root)).findings == []


def test_comments_and_strings_do_not_match():
    src = ('// app.post("/webhooks/stripe", (req, res) => { req.body; "checkout.session.completed" })\n'
           'const doc = "app.post(\'/webhooks/github\', (req) => req.headers[\'x-github-event\'])";\n')
    assert js(src) == ([], [])


def test_deno_supabase_edge_function():
    bad = ('import Stripe from "npm:stripe";\nDeno.serve(async (req) => {\n  const event = await req.json();\n'
           '  if (event.type === "checkout.session.completed") await supabase.from("orders").update({ paid: true });\n'
           '  return new Response("ok");\n});\n')
    findings, handlers = js(bad, "supabase/functions/stripe-webhook/index.ts")
    assert handlers[0].label == "POST /functions/v1/stripe-webhook"
    w = [f for f in findings if f.rule_id == "WHK001"]
    assert len(w) == 1 and "constructEventAsync" in w[0].fix and "await req.text()" in w[0].fix
    good = bad.replace("const event = await req.json();",
                       "const body = await req.text();\n  const event = await stripe.webhooks.constructEventAsync("
                       "body, req.headers.get(\"stripe-signature\")!, secret, undefined, cryptoProvider);")
    assert "WHK001" not in rules(js(good, "supabase/functions/stripe-webhook/index.ts")[0])


def test_imported_verify_helper_taking_the_request_counts():
    src = ('import { verifyAndParse } from "../lib/webhooks";\n'
           'export async function POST(req: Request) {\n  const event = await verifyAndParse(req);\n'
           '  if (event.type === "invoice.paid") await activate(event.data.object.customer);\n'
           '  return Response.json({ ok: true });\n}\n')
    findings, handlers = js('import Stripe from "stripe";\n' + src, "app/api/webhooks/stripe/route.ts")
    assert "WHK001" not in rules(findings)


def test_self_scan_is_clean():
    """The tool's own source is full of provider names, header names and snippets in strings."""
    res = scan_path(str(Path(__file__).parent.parent / "src"))
    assert res.findings == [] and res.handlers == []


def test_request_passed_to_imported_handler_is_not_guessed():
    src = ('import { handleWebhook } from "../lib/webhooks";\n'
           'export async function POST(req: Request) {\n  return handleWebhook(req);\n}\n')
    assert js('import Stripe from "stripe";\n' + src, "app/api/webhooks/stripe/route.ts") == ([], [])
