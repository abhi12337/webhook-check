# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-12

### Fixed

- A webhook route that never imports the provider's SDK and never names the provider in its
  code (for example `app/api/webhooks/stripe/route.ts` exporting `POST` that reads
  `event.type` from `await req.json()`) was skipped entirely, so WHK001 was not reported. Files
  are now selected by their path as well as their contents, and the provider is inferred from
  the route path (`/webhooks/stripe`), from its event types plus its name in the path, or from
  one provider's event types on a webhook path (`/api/webhooks`). Manual HMAC verification of
  the raw body still counts as verified, and `/api/stripe/checkout` is still not a webhook.
- WHK007 missed state changes made through a method call with a verb-style name
  (`db.markPaid(...)`, `this.orders.fulfillOrder(...)`, `db.mark_paid(...)`) while the same call
  without a receiver (`markPaid(...)`) was counted, so Express handlers were judged differently
  from Next.js / FastAPI ones. Both forms now count as writes in every framework.

## [0.1.0] - 2026-11-11

First release.

### Added

- `webhook-check scan [PATH ...]`: static scan of folders or single files. Never runs or
  imports the scanned code; no network access.
- `webhook-check rules`: every rule with why it matters and how to fix it.
- Handler discovery for Node/TypeScript (Next.js App Router and `pages/api`, Express, Hono,
  Fastify, NestJS, Koa-style routers, Deno / Supabase Edge Functions, Lambda-style functions;
  lexer-based) and Python (FastAPI / Starlette, Flask, Django / DRF; `ast`-based), following
  same-file helpers two levels deep.
- Providers: Stripe, Razorpay, GitHub, Clerk / Svix, Shopify, Paddle (Billing), Lemon Squeezy,
  Twilio, PayPal.
- Rules:
  - WHK001 webhook handler does not verify the signature
  - WHK002 signature checked against parsed / re-serialized JSON (`JSON.stringify`,
    `json.dumps`, `req.json()`, `express.json()` before the route, Next.js `pages/api` without
    `bodyParser: false`, Fastify without a raw parser)
  - WHK003 HMAC compared with `==` / `===` instead of a constant-time comparison
  - WHK004 hard-coded webhook signing secret (masked to at most 4 characters)
  - WHK005 verification failure caught and ignored, or boolean result unused
  - WHK006 Razorpay Checkout callback trusts `razorpay_payment_id` without `razorpay_signature`
  - WHK007 events not de-duplicated (heuristic)
  - WHK008 Stripe signature tolerance disabled or very large
- Text and JSON reports (JSON lists every handler found and whether it is verified), a
  provider- and framework-specific fix for every finding, `--fail-on`, `--min-severity`,
  `--disable`, `--exclude`, `--include-tests`, `--brief`, `--no-color`,
  `webhook-check: ignore` comments, exit codes `0` / `1` / `2`.
- Demo project generator (`examples/make_demo.py`) and a GitHub Actions example.
