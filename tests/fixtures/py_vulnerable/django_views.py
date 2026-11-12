"""Django webhook views with mistakes."""
import json

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from twilio.twiml.messaging_response import MessagingResponse

from .models import Order
from .sms import handle_command


@csrf_exempt
@require_POST
def stripe_webhook(request):
    event = json.loads(request.body)
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        Order.objects.filter(pk=session["metadata"]["order_id"]).update(paid=True)
    return HttpResponse(status=200)


@csrf_exempt
def sms_reply(request):
    body = request.POST.get("Body", "")
    resp = MessagingResponse()
    resp.message(handle_command(request.POST["From"], body))
    return HttpResponse(str(resp), content_type="application/xml")
