// Express server with several webhook mistakes.
import express from "express";
import crypto from "crypto";
import Stripe from "stripe";
import { validateWebhookSignature } from "razorpay/dist/utils/razorpay-utils";
import { Order, saveShopifyOrder, fulfillOrder, triggerDeploy } from "./models";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);
const app = express();
app.use(express.json());

const GITHUB_WEBHOOK_SECRET = "gh-hook-s3cret-2024-prod";

// GitHub: HMAC over re-serialized JSON, compared with ===
app.post("/webhooks/github", (req, res) => {
  const sig = req.get("x-hub-signature-256") || "";
  const digest = "sha256=" + crypto.createHmac("sha256", GITHUB_WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest("hex");
  if (sig === digest && req.get("x-github-event") === "push") {
    triggerDeploy(req.body.ref);
  }
  res.sendStatus(204);
});

// Stripe: express.json() already ran, failures are swallowed, tolerance of 30 days
app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"] as string,
      process.env.STRIPE_WEBHOOK_SECRET as string,
      60 * 60 * 24 * 30,
    );
  } catch (err) {
    console.warn("stripe signature check failed, continuing", err);
    event = req.body;
  }
  if (event.type === "checkout.session.completed") {
    await fulfillOrder(event.data.object.metadata.orderId);
  }
  res.json({ received: true });
});

// Razorpay webhook: the boolean result of validateWebhookSignature is ignored
app.post("/webhooks/razorpay", async (req, res) => {
  validateWebhookSignature(JSON.stringify(req.body), req.headers["x-razorpay-signature"] as string, process.env.RAZORPAY_WEBHOOK_SECRET as string);
  if (req.body.event === "order.paid") {
    await Order.updateOne({ razorpayOrderId: req.body.payload.order.entity.id }, { status: "paid" });
  }
  res.json({ ok: true });
});

// Razorpay Checkout callback: trusts the payment id sent by the browser
app.post("/api/payment/verify", async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id } = req.body;
  await Order.updateOne({ razorpayOrderId: razorpay_order_id }, { status: "paid", paymentId: razorpay_payment_id });
  res.json({ success: true });
});

// Shopify: no HMAC check at all
app.post("/webhooks/shopify/orders-create", async (req, res) => {
  const topic = req.get("X-Shopify-Topic");
  const shop = req.get("X-Shopify-Shop-Domain");
  await saveShopifyOrder(shop, topic, req.body);
  res.sendStatus(200);
});

app.listen(3000);
