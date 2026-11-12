// Stripe webhook without the SDK: verifies Stripe-Signature by hand (HMAC-SHA256 of
// "<t>.<raw body>", constant-time comparison) before trusting the event.
import crypto from "node:crypto";
import { db } from "@/lib/db";

export async function POST(req: Request) {
  const rawBody = await req.text();
  const header = req.headers.get("stripe-signature") ?? "";
  const parts = Object.fromEntries(header.split(",").map((kv) => kv.split("=")));
  const expected = crypto
    .createHmac("sha256", process.env.STRIPE_WEBHOOK_SECRET as string)
    .update(`${parts.t}.${rawBody}`)
    .digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(parts.v1 ?? "");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return new Response("Invalid signature", { status: 400 });
  }
  const event = JSON.parse(rawBody);
  const { rowCount } = await db.query(
    "insert into processed_webhook_events (id) values ($1) on conflict do nothing", [event.id]);
  if (rowCount === 0) return new Response("ok");
  if (event.type === "checkout.session.completed") {
    await db.markPaid(event.data.object.metadata.orderId);
  }
  return new Response("ok");
}
