// Hono app: Lemon Squeezy webhook verified with HMAC over the raw text, constant-time compare.
import { Hono } from "hono";
import { timingSafeEqual, createHmac } from "node:crypto";
import { grantAccess, alreadyProcessed } from "./billing";

const app = new Hono();

app.post("/webhooks/lemonsqueezy", async (c) => {
  const rawBody = await c.req.text();
  const signature = Buffer.from(c.req.header("X-Signature") ?? "");
  const digest = Buffer.from(createHmac("sha256", process.env.LEMONSQUEEZY_WEBHOOK_SECRET!).update(rawBody).digest("hex"));
  if (signature.length !== digest.length || !timingSafeEqual(digest, signature)) {
    return c.text("Invalid signature", 400);
  }
  const body = JSON.parse(rawBody);
  if (await alreadyProcessed(body.data.id, body.meta.event_name)) return c.json({ ok: true });
  if (body.meta.event_name === "order_created") {
    await grantAccess(body.data.attributes.user_email);
  }
  return c.json({ ok: true });
});

export default app;
