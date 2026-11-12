"""Python handlers (FastAPI, Flask, Django): true positives and verified handlers that must stay quiet."""

from pathlib import Path

import pytest

from conftest import py, rules
from webhook_check.scanner import scan_path

FIX = Path(__file__).parent / "fixtures"


def test_vulnerable_fixture_exact_findings():
    res = scan_path(str(FIX / "py_vulnerable"))
    got = sorted((f.rule_id, f.file, f.line, f.severity) for f in res.findings)
    assert got == sorted([
        ("WHK001", "django_views.py", 15, "critical"),
        ("WHK007", "django_views.py", 15, "low"),
        ("WHK001", "django_views.py", 24, "high"),
        ("WHK002", "fastapi_app.py", 18, "high"),
        ("WHK008", "fastapi_app.py", 18, "low"),
        ("WHK007", "fastapi_app.py", 13, "low"),
        ("WHK001", "fastapi_app.py", 26, "critical"),
        ("WHK007", "fastapi_app.py", 26, "low"),
        ("WHK004", "flask_app.py", 14, "high"),
        ("WHK003", "flask_app.py", 21, "medium"),
        ("WHK006", "flask_app.py", 30, "critical"),
        ("WHK002", "flask_app.py", 41, "high"),
        ("WHK005", "flask_app.py", 44, "high"),
        ("WHK007", "flask_app.py", 37, "low"),
    ])


def test_clean_fixture_no_findings_and_all_handlers_verified():
    res = scan_path(str(FIX / "py_clean"))
    assert res.findings == []
    assert len(res.handlers) == 8
    assert all(h.verified is True for h in res.handlers)
    assert {h.framework for h in res.handlers} == {"fastapi", "flask", "django"}


# ---------------------------------------------------------------- WHK001
def test_shopify_flask():
    bad = ('from flask import Flask, request\napp = Flask(__name__)\n'
           '@app.route("/webhooks/orders", methods=["POST"])\ndef orders():\n'
           '    topic = request.headers.get("X-Shopify-Topic")\n    save_order(request.get_json())\n    return "", 200\n')
    findings, handlers = py(bad)
    assert handlers[0].provider == "shopify"
    w = [f for f in findings if f.rule_id == "WHK001"]
    assert len(w) == 1 and "X-Shopify-Hmac-Sha256" in w[0].fix and "base64.b64encode" in w[0].fix
    good = bad.replace(
        '    topic = request.headers.get("X-Shopify-Topic")\n',
        '    digest = base64.b64encode(hmac.new(SECRET, request.get_data(), hashlib.sha256).digest()).decode()\n'
        '    if not hmac.compare_digest(digest, request.headers.get("X-Shopify-Hmac-Sha256", "")):\n'
        '        abort(401)\n')
    assert "WHK001" not in rules(py(good)[0])


def test_svix_fastapi_header_read_but_not_verified():
    src = ('from fastapi import FastAPI, Request\napp = FastAPI()\n@app.post("/clerk")\n'
           'async def clerk(request: Request):\n    svix_id = request.headers["svix-id"]\n'
           '    evt = await request.json()\n    await upsert_user(evt["data"], svix_id)\n    return {}\n')
    findings, handlers = py(src)
    assert handlers[0].provider == "svix"
    assert rules(findings) == ["WHK001"]


def test_lemonsqueezy_and_paypal():
    src = ('from flask import Flask, request\napp = Flask(__name__)\n'
           '@app.post("/lemon/webhook")\ndef lemon():\n    data = request.get_json()\n'
           '    if data["meta"]["event_name"] == "subscription_created":\n        grant_plan(data["data"]["id"])\n'
           '    return ""\n'
           '@app.post("/paypal/webhook")\ndef paypal():\n    event = request.get_json()\n'
           '    if event["event_type"] == "PAYMENT.CAPTURE.COMPLETED":\n        mark_paid(event["resource"]["id"])\n'
           '    return ""\n')
    findings, handlers = py(src)
    assert sorted(h.provider for h in handlers) == ["lemonsqueezy", "paypal"]
    assert rules(findings).count("WHK001") == 2


def test_unknown_decorator_is_opaque_but_verify_named_one_counts():
    base = ('from flask import Flask, request\napp = Flask(__name__)\n'
            '@app.post("/webhooks/stripe")\n%s\ndef hook():\n    event = request.get_json()\n'
            '    if event["type"] == "invoice.paid":\n        activate(event["data"])\n    return ""\n')
    assert "WHK001" not in rules(py(base % "@requires_partner")[0])
    assert "WHK001" not in rules(py(base % "@verify_stripe_signature")[0])
    assert "WHK001" in rules(py(base % "@login_required")[0])


def test_add_url_rule_and_class_based_view():
    src = ('from flask import Flask, request\nfrom flask.views import MethodView\napp = Flask(__name__)\n'
           'def gh():\n    if request.headers.get("X-GitHub-Event") == "push":\n        deploy()\n    return ""\n'
           'app.add_url_rule("/gh", view_func=gh, methods=["POST"])\n'
           'class StripeHook(MethodView):\n    def post(self):\n        e = request.get_json()\n'
           '        if e["type"] == "charge.refunded":\n            refund(e)\n        return ""\n')
    findings, handlers = py(src)
    assert sorted(h.label for h in handlers) == ["POST /gh", "StripeHook.post()"]
    assert rules(findings).count("WHK001") == 2


def test_non_webhook_routes_and_event_helpers_not_reported():
    src = ('import stripe\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n'
           '@app.post("/api/stripe/checkout")\nasync def checkout(request: Request):\n'
           '    body = await request.json()\n    return stripe.checkout.Session.create(line_items=body["items"])\n'
           'def handle_event(event):\n    if event["type"] == "checkout.session.completed":\n        fulfil(event)\n')
    assert py(src) == ([], [])


# ---------------------------------------------------------------- WHK002
@pytest.mark.parametrize("payload,hit", [
    ("request.data", False), ("request.get_data()", False), ("request.get_json()", True),
    ("json.dumps(request.json)", True), ("str(request.json)", True),
])
def test_flask_payload_sources(payload, hit):
    src = ('import json\nimport stripe\nfrom flask import Flask, request, abort\napp = Flask(__name__)\n'
           '@app.post("/stripe/webhook")\ndef hook():\n    try:\n'
           f'        event = stripe.Webhook.construct_event({payload}, request.headers["Stripe-Signature"], SECRET)\n'
           '    except Exception:\n        abort(400)\n    return ""\n')
    assert ("WHK002" in rules(py(src)[0])) is hit


def test_django_json_loads_then_hmac():
    src = ('import hashlib, hmac, json\n'
           'def github(request):\n    data = json.loads(request.body)\n'
           '    sig = request.headers.get("X-Hub-Signature-256", "")\n'
           '    mac = hmac.new(SECRET, json.dumps(data).encode(), hashlib.sha256).hexdigest()\n'
           '    if not hmac.compare_digest("sha256=" + mac, sig):\n        return HttpResponse(status=401)\n')
    findings, _ = py(src, "hooks/views.py")
    assert rules(findings) == ["WHK002"]


# ---------------------------------------------------------------- WHK003 / WHK005
def test_compare_negatives():
    src = ('import hashlib, hmac\n'
           'digest = hmac.new(KEY, body, hashlib.sha256).hexdigest()\n'
           'if len(digest) != len(sig):\n    pass\n'
           'if digest == "":\n    pass\n'
           'token_hash = hashlib.sha256(token.encode()).hexdigest()\n'
           'if token_hash == stored_hash:\n    pass\n')
    assert "WHK003" not in rules(py(src)[0])


def test_inline_compare_and_hmac_object():
    src = ('import base64, hashlib, hmac\n'
           'if base64.b64encode(hmac.new(KEY, body, hashlib.sha256).digest()).decode() == header:\n    pass\n'
           'h = hmac.new(KEY, body, hashlib.sha256)\nexpected = h.hexdigest()\n'
           'if header != expected:\n    pass\n')
    findings, _ = py(src)
    assert [(f.rule_id, f.line) for f in findings] == [("WHK003", 2), ("WHK003", 6)]


def test_compare_digest_result_ignored():
    src = 'import hmac\nhmac.compare_digest(expected, received)\nif not hmac.compare_digest(expected, received):\n    raise X\n'
    assert [(f.rule_id, f.line) for f in py(src)[0]] == [("WHK005", 2)]


def test_except_variants():
    base = ('import stripe\ndef hook(request):\n    try:\n'
            '        event = stripe.Webhook.construct_event(request.body, sig, SECRET)\n'
            '    except stripe.error.SignatureVerificationError:\n%s\n    return 200\n')
    assert "WHK005" in rules(py(base % "        logger.warning('bad sig')")[0])
    assert "WHK005" in rules(py(base % "        event = json.loads(request.body)")[0])
    assert "WHK005" not in rules(py(base % "        return HttpResponse(status=400)")[0])
    assert "WHK005" not in rules(py(base % "        abort(400)")[0])
    assert "WHK005" not in rules(py(base % "        event = None\n    if event is None:\n        return 400")[0])


def test_unrelated_try_not_reported():
    src = 'def f(form):\n    try:\n        form.validate()\n    except ValueError:\n        log("x")\n'
    assert py(src) == ([], [])


# ---------------------------------------------------------------- WHK004
def test_secrets(fake):
    src = (f'STRIPE_WEBHOOK_SECRET = "{fake["whsec"]}"\n'
           f'GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "{fake["generic"]}")\n'
           f'mac = hmac.new(b"{fake["generic"]}x", body, hashlib.sha256)\n'
           f'settings = {{"shopify_webhook_secret": "{fake["generic"]}y"}}\n'
           f'v = RequestValidator("{fake["generic"]}z")\n'
           f'PLACEHOLDER_WEBHOOK_SECRET = "whsec_your_secret_here"\n'
           f'OTHER = os.getenv("WEBHOOK_SECRET", "")\n')
    findings, _ = py(src, "settings.py")
    got = [(f.rule_id, f.line, f.severity) for f in findings]
    assert got == [("WHK004", 1, "critical"), ("WHK004", 2, "high"), ("WHK004", 3, "high"),
                   ("WHK004", 4, "high"), ("WHK004", 5, "high")]
    for f in findings:
        for text in (f.message, f.evidence):
            assert fake["whsec"] not in text and fake["generic"][:8] not in text


# ---------------------------------------------------------------- WHK006 / WHK007 / WHK008
def test_razorpay_payment_django():
    bad = ('from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef paid(request):\n'
           '    pid = request.POST["razorpay_payment_id"]\n    Order.objects.filter(rzp=pid).update(paid=True)\n')
    findings, _ = py(bad, "shop/views.py")
    assert [(f.rule_id, f.line) for f in findings] == [("WHK006", 4)]
    good = bad.replace('    Order.objects', '    client.utility.verify_payment_signature(request.POST)\n    Order.objects')
    assert py(good, "shop/views.py")[0] == []


def test_dedupe_evidence():
    src = ('import stripe\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n@app.post("/webhooks/stripe")\n'
           'async def hook(request: Request):\n    payload = await request.body()\n'
           '    event = stripe.Webhook.construct_event(payload, request.headers["stripe-signature"], SECRET)\n'
           '    %s\n    await db.execute("update orders set paid = true")\n    return {}\n')
    assert "WHK007" in rules(py(src % "pass")[0])
    assert "WHK007" not in rules(py(src % 'if await already_processed(event["id"]): return {}')[0])


@pytest.mark.parametrize("arg,hit", [("300", False), ("tolerance=600", False), ("tolerance=0", True),
                                     ("tolerance=24 * 3600", True), ('tolerance=float("inf")', True)])
def test_tolerance(arg, hit):
    src = f"import stripe\nevent = stripe.Webhook.construct_event(payload, sig, secret, {arg})\n"
    assert ("WHK008" in rules(py(src)[0])) is hit


def test_syntax_error_does_not_crash():
    assert py("def broken(:\n    stripe-signature\n") == ([], [])


def test_django_meta_headers():
    src = ('import stripe\nfrom django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef hook(request):\n'
           '    sig = request.META["HTTP_STRIPE_SIGNATURE"]\n    event = json.loads(request.body)\n'
           '    Order.objects.filter(pk=event["data"]["object"]["id"]).update(paid=True)\n    return HttpResponse()\n')
    findings, handlers = py(src, "shop/views.py")
    assert handlers[0].provider == "stripe" and "WHK001" in rules(findings)
    good = src.replace('    event = json.loads(request.body)\n',
                       '    event = stripe.Webhook.construct_event(request.body, sig, SECRET)\n')
    assert "WHK001" not in rules(py(good, "shop/views.py")[0])
