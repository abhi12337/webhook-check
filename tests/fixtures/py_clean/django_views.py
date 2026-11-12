"""Django webhook views done right."""
import os

import stripe
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from svix.webhooks import Webhook, WebhookVerificationError
from twilio.request_validator import RequestValidator
from twilio.twiml.messaging_response import MessagingResponse

from .models import Order, ProcessedEvent, sync_user
from .sms import handle_command


@csrf_exempt
@require_POST
def stripe_webhook(request):
    try:
        event = stripe.Webhook.construct_event(
            request.body, request.headers.get("Stripe-Signature", ""), os.environ["STRIPE_WEBHOOK_SECRET"]
        )
    except (ValueError, stripe.error.SignatureVerificationError):
        return HttpResponse(status=400)
    _, created = ProcessedEvent.objects.get_or_create(id=event["id"])
    if not created:
        return HttpResponse(status=200)
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        Order.objects.filter(pk=session["metadata"]["order_id"]).update(paid=True)
    return HttpResponse(status=200)


@csrf_exempt
def clerk_webhook(request):
    headers = {
        "svix-id": request.headers.get("svix-id", ""),
        "svix-timestamp": request.headers.get("svix-timestamp", ""),
        "svix-signature": request.headers.get("svix-signature", ""),
    }
    try:
        evt = Webhook(os.environ["CLERK_WEBHOOK_SIGNING_SECRET"]).verify(request.body, headers)
    except WebhookVerificationError:
        return HttpResponse(status=400)
    if evt["type"] in ("user.created", "user.updated"):
        sync_user(evt["data"], delivery=headers["svix-id"])
    return HttpResponse(status=204)


@csrf_exempt
def sms_reply(request):
    validator = RequestValidator(os.environ["TWILIO_AUTH_TOKEN"])
    if not validator.validate(request.build_absolute_uri(), request.POST, request.headers.get("X-Twilio-Signature", "")):
        return HttpResponse(status=403)
    resp = MessagingResponse()
    resp.message(handle_command(request.POST["From"], request.POST.get("Body", "")))
    return HttpResponse(str(resp), content_type="application/xml")
