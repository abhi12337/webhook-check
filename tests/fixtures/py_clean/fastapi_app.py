"""FastAPI webhooks done right."""
import hashlib
import hmac
import os
import time

import stripe
from fastapi import FastAPI, HTTPException, Request

from .billing import activate_subscription, mark_invoice_paid, record_event

app = FastAPI()


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, os.environ["STRIPE_WEBHOOK_SECRET"])
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid signature")
    if not await record_event(event["id"]):
        return {"ok": True}
    if event["type"] == "invoice.paid":
        await mark_invoice_paid(event["data"]["object"]["subscription"])
    return {"ok": True}


def paddle_signature_ok(payload: bytes, header: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(";") if "=" in p)
    signed = parts.get("ts", "").encode() + b":" + payload
    expected = hmac.new(os.environ["PADDLE_WEBHOOK_SECRET"].encode(), signed, hashlib.sha256).hexdigest()
    fresh = abs(time.time() - int(parts.get("ts", "0"))) < 300
    return fresh and hmac.compare_digest(expected, parts.get("h1", ""))


@app.post("/webhooks/paddle")
async def paddle_webhook(request: Request):
    payload = await request.body()
    if not paddle_signature_ok(payload, request.headers.get("Paddle-Signature", "")):
        raise HTTPException(status_code=400, detail="Invalid signature")
    event = await request.json()
    if not await record_event(event["event_id"]):
        return {"ok": True}
    if event["event_type"] == "transaction.completed":
        await activate_subscription(event["data"]["customer_id"])
    return {"ok": True}
