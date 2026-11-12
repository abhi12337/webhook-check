// Hono app: Lemon Squeezy webhook with no X-Signature check.
import { Hono } from "hono";
import { grantAccess } from "./billing";

const app = new Hono();

app.post("/webhooks/lemonsqueezy", async (c) => {
  const body = await c.req.json();
  const eventName = c.req.header("X-Event-Name");
  if (eventName === "order_created") {
    await grantAccess(body.data.attributes.user_email);
  }
  return c.json({ ok: true });
});

export default app;
