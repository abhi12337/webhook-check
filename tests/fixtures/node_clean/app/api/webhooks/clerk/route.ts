// Clerk webhook done right: Clerk's verifyWebhook() reads the raw body and svix headers.
import { verifyWebhook } from "@clerk/nextjs/webhooks";
import { createUser, deleteUser } from "@/lib/users";

export async function POST(req: Request) {
  let evt;
  try {
    evt = await verifyWebhook(req);
  } catch (err) {
    return new Response("Invalid signature", { status: 400 });
  }
  const svixId = req.headers.get("svix-id");
  if (evt.type === "user.created") await createUser(evt.data.id, svixId);
  if (evt.type === "user.deleted") await deleteUser(evt.data.id!, svixId);
  return new Response("ok");
}
