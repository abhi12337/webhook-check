// Creates a Checkout Session through Stripe's REST API (no SDK): not a webhook.
export async function POST(req: Request) {
  const { priceId } = await req.json();
  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}` },
    body: new URLSearchParams({ mode: "payment", "line_items[0][price]": priceId, "line_items[0][quantity]": "1" }),
  });
  return Response.json(await res.json());
}
