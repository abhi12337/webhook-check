"""Flask webhooks with mistakes."""
import hashlib
import hmac
import json
import os

import razorpay
from flask import Flask, abort, redirect, request

from .models import Order, db, run_ci

app = Flask(__name__)
client = razorpay.Client(auth=(os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"]))
GITHUB_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "dev-gh-hook-secret-1234")


@app.route("/webhooks/github", methods=["POST"])
def github_webhook():
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(GITHUB_SECRET.encode(), request.get_data(), hashlib.sha256).hexdigest()
    if signature != expected:
        abort(401)
    if request.headers.get("X-GitHub-Event") == "push":
        run_ci(request.get_json()["after"])
    return "", 204


@app.post("/payment/success")
def payment_success():
    payment_id = request.form["razorpay_payment_id"]
    order_id = request.form["razorpay_order_id"]
    Order.query.filter_by(rzp_order_id=order_id).update({"status": "paid", "payment_id": payment_id})
    db.session.commit()
    return redirect("/thank-you")


@app.post("/webhooks/razorpay")
def razorpay_webhook():
    payload = request.get_json()
    try:
        client.utility.verify_webhook_signature(
            json.dumps(payload), request.headers["X-Razorpay-Signature"], os.environ["RAZORPAY_WEBHOOK_SECRET"]
        )
    except razorpay.errors.SignatureVerificationError:
        app.logger.warning("bad razorpay signature")
    if payload["event"] == "payment.captured":
        Order.query.filter_by(rzp_order_id=payload["payload"]["payment"]["entity"]["order_id"]).update({"status": "paid"})
        db.session.commit()
    return "", 200
