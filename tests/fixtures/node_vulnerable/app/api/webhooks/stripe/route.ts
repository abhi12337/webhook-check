// Next.js App Router Stripe webhook that trusts the body without checking Stripe-Signature.
import Stripe from "stripe";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const event = (await req.json()) as Stripe.Event;

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      await db.order.update({ where: { id: session.metadata!.orderId }, data: { status: "paid" } });
      break;
    }
    case "customer.subscription.deleted":
      await db.subscription.delete({ where: { stripeId: event.data.object.id } });
      break;
  }
  return NextResponse.json({ received: true });
}
