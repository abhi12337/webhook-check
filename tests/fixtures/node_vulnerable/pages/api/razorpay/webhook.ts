// Next.js pages/api Razorpay webhook: HMAC over JSON.stringify(req.body), compared with !==.
import crypto from "crypto";
import type { NextApiRequest, NextApiResponse } from "next";
import { markOrderPaid } from "../../../lib/orders";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const signature = req.headers["x-razorpay-signature"] as string;
  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET as string)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (expected !== signature) {
    return res.status(400).json({ error: "bad signature" });
  }

  if (req.body.event === "payment.captured") {
    await markOrderPaid(req.body.payload.payment.entity.order_id);
  }
  res.status(200).json({ ok: true });
}
