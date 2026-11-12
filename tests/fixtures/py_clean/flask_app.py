"""Flask webhooks done right."""
import hashlib
import hmac
import os

import razorpay
from flask import Flask, abort, redirect, request

from .models import Order, ProcessedEvent, db, run_ci

app = Flask(__name__)
client = razorpay.Client(auth=(os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"]))
GITHUB_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]


@app.route("/webhooks/github", methods=["POST"])
def github_webhook():
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(GITHUB_SECRET.encode(), request.get_data(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(401)
    if ProcessedEvent.seen(request.headers.get("X-GitHub-Delivery")):
        return "", 204
    if request.headers.get("X-GitHub-Event") == "push":
        run_ci(request.get_json()["after"])
    return "", 204


@app.post("/payment/success")
def payment_success():
    payment_id = request.form["razorpay_payment_id"]
    order = Order.query.filter_by(user_id=current_user_id(), status="created").first_or_404()
    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": order.rzp_order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": request.form["razorpay_signature"],
        })
    except razorpay.errors.SignatureVerificationError:
        abort(400)
    order.status = "paid"
    db.session.commit()
    return redirect("/thank-you")


@app.post("/webhooks/razorpay")
def razorpay_webhook():
    body = request.get_data(as_text=True)
    try:
        client.utility.verify_webhook_signature(
            body, request.headers.get("X-Razorpay-Signature", ""), os.environ["RAZORPAY_WEBHOOK_SECRET"]
        )
    except razorpay.errors.SignatureVerificationError:
        abort(400)
    if ProcessedEvent.seen(request.headers.get("X-Razorpay-Event-Id")):
        return "", 200
    payload = request.get_json()
    if payload["event"] == "payment.captured":
        Order.query.filter_by(rzp_order_id=payload["payload"]["payment"]["entity"]["order_id"]).update({"status": "paid"})
        db.session.commit()
    return "", 200


def current_user_id():
    return 1
