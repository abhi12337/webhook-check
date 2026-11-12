// Express server with correctly verified webhooks. Webhook routes are registered with
// express.raw() BEFORE app.use(express.json()).
import express from "express";
import crypto from "crypto";
import Stripe from "stripe";
import { validatePaymentVerification } from "razorpay/dist/utils/razorpay-utils";
import { Order, saveShopifyOrder, fulfillOrder, triggerDeploy, seenDelivery } from "./models";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);
const app = express();

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

app.post("/webhooks/github", express.raw({ type: "application/json" }), (req, res) => {
  const sig = String(req.headers["x-hub-signature-256"] ?? "");
  const digest = "sha256=" + crypto.createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET as string).update(req.body).digest("hex");
  if (!safeEqual(digest, sig)) return res.status(401).end();
  if (seenDelivery(req.headers["x-github-delivery"])) return res.status(200).end();
  const payload = JSON.parse(req.body.toString("utf8"));
  if (req.headers["x-github-event"] === "push") triggerDeploy(payload.ref);
  res.sendStatus(204);
});

app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"] as string, process.env.STRIPE_WEBHOOK_SECRET as string);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${(err as Error).message}`);
  }
  if (await Order.exists({ stripeEventId: event.id })) return res.json({ received: true });
  if (event.type === "checkout.session.completed") {
    await fulfillOrder((event.data.object as Stripe.Checkout.Session).metadata!.orderId);
  }
  res.json({ received: true });
});

app.post("/webhooks/shopify/orders-create", express.raw({ type: "application/json" }), async (req, res) => {
  const hmac = String(req.get("X-Shopify-Hmac-Sha256") ?? "");
  const digest = crypto.createHmac("sha256", process.env.SHOPIFY_API_SECRET as string).update(req.body).digest("base64");
  if (!safeEqual(digest, hmac)) return res.sendStatus(401);
  await saveShopifyOrder(req.get("X-Shopify-Webhook-Id"), req.get("X-Shopify-Shop-Domain"), JSON.parse(req.body.toString()));
  res.sendStatus(200);
});

app.use(express.json());

// Razorpay Checkout callback: signature verified against the order we stored
app.post("/api/payment/verify", async (req, res) => {
  const { razorpay_payment_id, razorpay_signature } = req.body;
  const order = await Order.findOne({ user: req.user.id, status: "created" });
  const ok = validatePaymentVerification(
    { order_id: order.razorpayOrderId, payment_id: razorpay_payment_id },
    razorpay_signature,
    process.env.RAZORPAY_KEY_SECRET as string,
  );
  if (!ok) return res.status(400).json({ error: "invalid signature" });
  await Order.updateOne({ _id: order._id }, { status: "paid", paymentId: razorpay_payment_id });
  res.json({ success: true });
});

// Not a webhook: creates a Checkout Session (must not be reported)
app.post("/api/stripe/checkout", async (req, res) => {
  const session = await stripe.checkout.sessions.create({ mode: "payment", line_items: req.body.items });
  res.json({ url: session.url });
});

app.listen(3000);
