import { createHmac, randomUUID } from "node:crypto";

const issuer = requireValue("FILE_GRANT_ISSUER");
const audience = requireValue("FILE_GRANT_AUDIENCE");
const key = Buffer.from(requireValue("FILE_GRANT_HMAC_KEY"), "base64url");
const [chatId, fileName, sizeValue, deliveryValue = "document"] = process.argv.slice(2);
const fileSize = Number(sizeValue);
if (
  !chatId
  || !fileName
  || !Number.isSafeInteger(fileSize)
  || fileSize < 1
  || (deliveryValue !== "document" && deliveryValue !== "photo")
) {
  throw new Error(
    "Usage: tsx examples/sign-send-grant.ts <telegram-chat-id> <file-name> <file-size> [document|photo]",
  );
}

const now = Math.floor(Date.now() / 1000);
const header = encode({ alg: "HS256", typ: "JWT" });
const payload = encode({
  iss: issuer,
  aud: audience,
  iat: now,
  exp: now + 300,
  jti: randomUUID(),
  op: "send_file",
  telegram_chat_id: chatId,
  telegram_message_thread_id: null,
  delivery: deliveryValue,
  file_name: fileName,
  mime_type: "application/octet-stream",
  caption: null,
  file_size: fileSize,
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
