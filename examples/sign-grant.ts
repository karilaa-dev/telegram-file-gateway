import { createHmac, randomUUID } from "node:crypto";

const issuer = requireValue("FILE_GRANT_ISSUER");
const audience = requireValue("FILE_GRANT_AUDIENCE");
const key = Buffer.from(requireValue("FILE_GRANT_HMAC_KEY"), "base64url");
const telegramFileId = process.argv[2];
if (!telegramFileId) throw new Error("Usage: tsx examples/sign-grant.ts <telegram-file-id>");

const now = Math.floor(Date.now() / 1000);
const header = encode({ alg: "HS256", typ: "JWT" });
const payload = encode({
  iss: issuer,
  aud: audience,
  iat: now,
  exp: now + 300,
  jti: randomUUID(),
  op: "download_file",
  telegram_file_id: telegramFileId,
  max_bytes: 20 * 1024 * 1024,
});
const signature = createHmac("sha256", key).update(`${header}.${payload}`).digest("base64url");
process.stdout.write(`${header}.${payload}.${signature}\n`);

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function requireValue(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}
