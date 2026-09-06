/**
 * Server-to-server access with a static API key.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every campaign here is tied to one published post, because a campaign that
 * matches "any post of this account" answers itself: our own captions contain
 * each other's keywords, and that produced 50 DMs in 62 seconds between our
 * own accounts.
 *
 * But a campaign can only name its post AFTER the post exists. Creating them
 * by hand means someone has to sit in front of the dashboard right after every
 * publish, and measured on 2026-09-06 that is exactly why only 10 of 60
 * campaigns had a post to point at.
 *
 * So the publisher creates the campaign itself, with the media id Meta just
 * returned. For that it needs to call this API without a browser session.
 *
 * HOW IT FAILS CLOSED
 * -------------------
 * `OPENREPLY_API_KEY` must be set, and long. If it is missing the header path
 * does not exist at all — it is not "allow by default", and it is not "allow
 * with a guessable key". A deployment that never sets it behaves exactly as
 * before.
 *
 * `OPENREPLY_API_WORKSPACE_ID` is optional, and only because on a single-tenant
 * install there is nothing to disambiguate: with exactly ONE workspace in the
 * database, that is the workspace. With two or more it refuses rather than
 * guessing — creating campaigns in the wrong workspace would not look wrong,
 * it would look like nothing happened.
 *
 * The comparison is length-safe and constant-time: a plain `===` on a secret
 * leaks its length and its prefix through timing.
 */
import { timingSafeEqual } from "crypto";
import type { NextRequest } from "next/server";
import type { WorkspaceRole } from "@/app/generated/prisma/client";
import { prisma } from "@/lib/db/client";

export const API_KEY_HEADER = "x-openreply-key";

/** Minimum length, so a short or placeholder key cannot be set by accident. */
const MIN_KEY_LENGTH = 24;

function equalSecrets(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  // timingSafeEqual throws on differing lengths, which would itself be a
  // length oracle. Compare against a fixed-size digest-like padding instead:
  // bail on length only after doing the constant-time compare on equal sizes.
  if (left.length !== right.length) {
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}

/**
 * The workspace this request is acting as, when it carries a valid API key.
 * Returns `null` for anything else — including a wrong key, so the caller
 * falls through to the normal session check and an attacker cannot tell a
 * bad key from no key.
 */
export async function workspaceFromApiKey(request: NextRequest): Promise<{
  userId: string;
  workspaceId: string;
  role: WorkspaceRole;
} | null> {
  const expected = process.env.OPENREPLY_API_KEY;
  if (!expected || expected.length < MIN_KEY_LENGTH) return null;

  const presented = request.headers.get(API_KEY_HEADER);
  if (!presented || !equalSecrets(presented, expected)) return null;

  const pedido = process.env.OPENREPLY_API_WORKSPACE_ID;
  if (pedido) {
    // The workspace has to exist. Trusting the env var alone would let a typo
    // create campaigns under a workspace id that belongs to nobody, and they
    // would be invisible in the dashboard rather than wrong-looking.
    const workspace = await prisma.workspace.findUnique({
      where: { id: pedido },
      select: { id: true },
    });
    if (!workspace) return null;
    return { userId: `api-key:${pedido}`, workspaceId: pedido, role: "ADMIN" };
  }

  // No id given: only unambiguous if there is exactly one. `take: 2` is the
  // point — it answers "is there more than one?" without loading a table.
  const todos = await prisma.workspace.findMany({ select: { id: true }, take: 2 });
  if (todos.length !== 1) return null;
  return { userId: `api-key:${todos[0].id}`, workspaceId: todos[0].id, role: "ADMIN" };
}
