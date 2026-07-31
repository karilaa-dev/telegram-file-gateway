export const MAX_FILE_BYTES = 20 * 1024 * 1024;
export const MAX_GRANT_LIFETIME_SECONDS = 5 * 60;

export interface TelegramFileGrantV1 {
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  telegram_file_id: string;
  max_bytes: number;
}

export type VerifiedGrant = TelegramFileGrantV1;

type JwtHeader = {
  alg: "HS256";
  typ: "JWT";
};

export async function verifyFileGrant(
  token: string,
  input: {
    key: string;
    issuer: string;
    audience: string;
    nowSeconds?: number;
  },
): Promise<VerifiedGrant> {
  if (token.length > 4096) throw new Error("invalid grant");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid grant");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new Error("invalid grant");

  const header = parseJson<JwtHeader>(decodeBase64Url(encodedHeader));
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

  const grant = parseJson<Record<string, unknown>>(decodeBase64Url(encodedPayload));
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
    || typeof grant.telegram_file_id !== "string"
    || grant.telegram_file_id.length < 1
    || grant.telegram_file_id.length > 512
    || !isInteger(grant.max_bytes)
    || grant.max_bytes < 1
    || grant.max_bytes > MAX_FILE_BYTES
  ) {
    throw new Error("invalid grant");
  }
  return grant as unknown as TelegramFileGrantV1;
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

function parseJson<T>(bytes: Uint8Array): T {
  if (bytes.byteLength > 2048) throw new Error("invalid grant");
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid");
    return parsed as T;
  } catch {
    throw new Error("invalid grant");
  }
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}
