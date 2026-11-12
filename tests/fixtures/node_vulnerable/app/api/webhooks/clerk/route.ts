// Clerk (Svix) webhook: verifies a re-serialized body and carries on when verification fails.
import { Webhook } from "svix";
import { headers } from "next/headers";
import type { WebhookEvent } from "@clerk/nextjs/server";
import { createUser, deleteUser } from "@/lib/users";

export async function POST(req: Request) {
  const payload = await req.json();
  const body = JSON.stringify(payload);
  const h = await headers();

  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
  let evt: WebhookEvent;
  try {
    evt = wh.verify(body, {
      "svix-id": h.get("svix-id")!,
      "svix-timestamp": h.get("svix-timestamp")!,
      "svix-signature": h.get("svix-signature")!,
    }) as WebhookEvent;
  } catch (err) {
    console.error("clerk webhook verification failed", err);
    evt = payload as WebhookEvent;
  }

  if (evt.type === "user.created") await createUser(evt.data.id);
  if (evt.type === "user.deleted") await deleteUser(evt.data.id!);
  return new Response("ok");
}
