// Next.js pages/api Razorpay webhook done right: bodyParser off, HMAC of the raw bytes,
// timingSafeEqual, X-Razorpay-Event-Id recorded.
import crypto from "crypto";
import type { NextApiRequest, NextApiResponse } from "next";
import { markOrderPaid, rememberEvent } from "../../../lib/orders";

export const config = { api: { bodyParser: false } };

async function readRaw(req: NextApiRequest): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  return Buffer.concat(chunks);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const rawBody = await readRaw(req);
  const signature = String(req.headers["x-razorpay-signature"] ?? "");
  const expected = crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET as string).update(rawBody).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(400).json({ error: "bad signature" });
  }
  const body = JSON.parse(rawBody.toString("utf8"));
  if (!(await rememberEvent(req.headers["x-razorpay-event-id"]))) return res.status(200).end();
  if (body.event === "payment.captured") {
    await markOrderPaid(body.payload.payment.entity.order_id);
  }
  res.status(200).json({ ok: true });
}
