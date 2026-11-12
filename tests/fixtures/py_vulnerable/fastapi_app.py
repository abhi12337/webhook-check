"""FastAPI webhooks with mistakes."""
import json
import os

import stripe
from fastapi import FastAPI, HTTPException, Request

from .billing import activate_subscription, mark_invoice_paid

app = FastAPI()


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    data = await request.json()
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(json.dumps(data), sig, os.environ["STRIPE_WEBHOOK_SECRET"], tolerance=None)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="bad signature")
    if event["type"] == "invoice.paid":
        await mark_invoice_paid(event["data"]["object"]["subscription"])
    return {"ok": True}


@app.post("/webhooks/paddle")
async def paddle_webhook(request: Request):
    payload = await request.json()
    if payload["event_type"] == "transaction.completed":
        await activate_subscription(payload["data"]["customer_id"])
    return {"ok": True}
