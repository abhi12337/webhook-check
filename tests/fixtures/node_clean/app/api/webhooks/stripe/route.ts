// Next.js App Router Stripe webhook done right: raw text, constructEvent, 400 on failure, dedupe.
import Stripe from "stripe";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const rawBody = await req.text();
  const signature = req.headers.get("stripe-signature") ?? "";

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    return new Response("Invalid signature", { status: 400 });
  }

  const inserted = await db.processedEvent.createMany({ data: [{ id: event.id }], skipDuplicates: true });
  if (inserted.count === 0) return NextResponse.json({ received: true });

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      await db.order.update({ where: { id: session.metadata!.orderId }, data: { status: "paid" } });
      break;
    }
  }
  return NextResponse.json({ received: true });
}
