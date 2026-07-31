export const MAX_FILE_BYTES = 20 * 1024 * 1024;
export const MAX_GRANT_LIFETIME_SECONDS = 5 * 60;

interface TelegramGrantBaseV1 {
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  max_bytes: number;
}

export interface TelegramFileGrantV1 extends TelegramGrantBaseV1 {
  op: "download_file";
  telegram_file_id: string;
}

export interface TelegramSendGrantV1 extends TelegramGrantBaseV1 {
  op: "send_file";
  telegram_chat_id: string;
  telegram_message_thread_id: number | null;
  delivery: "document" | "photo";
  file_name: string;
  mime_type: string;
  caption: string | null;
  file_size: number;
}

type GrantVerificationInput = {
  key: string;
  issuer: string;
  audience: string;
  nowSeconds?: number;
};

export async function verifyFileGrant(
  token: string,
  input: GrantVerificationInput,
): Promise<TelegramFileGrantV1> {
  const grant = await verifyGrant(token, input);
  if (
    grant.op !== "download_file"
    || typeof grant.telegram_file_id !== "string"
    || grant.telegram_file_id.length < 1
    || grant.telegram_file_id.length > 512
  ) {
    throw new Error("invalid grant");
  }
  return {
    ...baseGrant(grant),
    op: "download_file",
    telegram_file_id: grant.telegram_file_id,
  };
}

export async function verifySendGrant(
  token: string,
  input: GrantVerificationInput,
): Promise<TelegramSendGrantV1> {
  const grant = await verifyGrant(token, input);
  if (
    grant.op !== "send_file"
    || typeof grant.telegram_chat_id !== "string"
    || !/^-?[1-9]\d{0,19}$/.test(grant.telegram_chat_id)
    || !isNullablePositiveInteger(grant.telegram_message_thread_id)
    || (grant.delivery !== "document" && grant.delivery !== "photo")
    || typeof grant.file_name !== "string"
    || grant.file_name.length < 1
    || grant.file_name.length > 255
    || /[\r\n\0]/.test(grant.file_name)
    || typeof grant.mime_type !== "string"
    || grant.mime_type.length < 1
    || grant.mime_type.length > 255
    || !/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(grant.mime_type)
    || !isNullableCaption(grant.caption)
    || !isInteger(grant.file_size)
    || grant.file_size < 1
    || grant.file_size > (grant.max_bytes as number)
  ) {
    throw new Error("invalid grant");
  }
  return {
    ...baseGrant(grant),
    op: "send_file",
    telegram_chat_id: grant.telegram_chat_id,
    telegram_message_thread_id: grant.telegram_message_thread_id,
    delivery: grant.delivery,
    file_name: grant.file_name,
    mime_type: grant.mime_type,
    caption: grant.caption,
    file_size: grant.file_size,
  };
}

async function verifyGrant(
  token: string,
  input: GrantVerificationInput,
): Promise<Record<string, unknown>> {
  if (token.length > 8192) throw new Error("invalid grant");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid grant");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new Error("invalid grant");

  const header = parseJson(decodeBase64Url(encodedHeader));
  if (header.alg !== "HS256" || header.typ !== "JWT") throw new Error("invalid grant");

  const keyBytes = decodeConfiguredKey(input.key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "HMAC",
    cryptoKey,
    decodeBase64Url(encodedSignature),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
  );
  if (!valid) throw new Error("invalid grant");

  const grant = parseJson(decodeBase64Url(encodedPayload));
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (
    grant.iss !== input.issuer
    || grant.aud !== input.audience
    || !isInteger(grant.iat)
    || !isInteger(grant.exp)
    || grant.iat > now + 30
    || grant.exp <= now
    || grant.exp <= grant.iat
    || grant.exp - grant.iat > MAX_GRANT_LIFETIME_SECONDS
    || typeof grant.jti !== "string"
    || grant.jti.length < 16
    || grant.jti.length > 128
    || !isInteger(grant.max_bytes)
    || grant.max_bytes < 1
    || grant.max_bytes > MAX_FILE_BYTES
  ) {
    throw new Error("invalid grant");
  }
  return grant;
}

function baseGrant(grant: Record<string, unknown>): TelegramGrantBaseV1 {
  return {
    iss: grant.iss as string,
    aud: grant.aud as string,
    iat: grant.iat as number,
    exp: grant.exp as number,
    jti: grant.jti as string,
    max_bytes: grant.max_bytes as number,
  };
}

function decodeConfiguredKey(value: string): Uint8Array<ArrayBuffer> {
  const decoded = decodeBase64Url(value);
  if (decoded.byteLength < 32) throw new Error("invalid gateway configuration");
  return decoded;
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid grant");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("invalid grant");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseJson(bytes: Uint8Array): Record<string, unknown> {
  if (bytes.byteLength > 4096) throw new Error("invalid grant");
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid");
    return Object.fromEntries(Object.entries(parsed));
  } catch {
    throw new Error("invalid grant");
  }
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isNullablePositiveInteger(value: unknown): value is number | null {
  return value === null || (isInteger(value) && value > 0);
}

function isNullableCaption(value: unknown): value is string | null {
  return value === null
    || (typeof value === "string" && Array.from(value).length <= 1024 && !value.includes("\0"));
}
