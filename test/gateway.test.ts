import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import worker, { type Env } from "../src/index";

const secret = "A".repeat(43);
const env: Env = {
  TELEGRAM_BOT_TOKEN: "123456:secret-token",
  FILE_GRANT_HMAC_KEY: secret,
  FILE_GRANT_ISSUER: "test-client",
  FILE_GRANT_AUDIENCE: "telegram-file-gateway",
};
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("telegram file gateway", () => {
  it("reports health without contacting Telegram", async () => {
    const calls: unknown[][] = [];
    globalThis.fetch = mockFetch(calls, []);
    const response = await invoke("/healthz");
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, service: "telegram-file-gateway" });
    assert.equal(calls.length, 0);
  });

  it("streams a granted Telegram file without redirecting or exposing credentials", async () => {
    const bytes = new TextEncoder().encode("telegram fixture");
    const calls: unknown[][] = [];
    globalThis.fetch = mockFetch(calls, [
      new Response(JSON.stringify({
        ok: true,
        result: { file_size: bytes.length, file_path: "documents/file_42.bin" },
      }), { status: 200, headers: { "content-type": "application/json" } }),
      new Response(bytes, {
        status: 200,
        headers: { "content-type": "application/octet-stream", "content-length": String(bytes.length) },
      }),
    ]);

    const response = await invoke("/v1/file", await grant());
    assert.equal(response.status, 200);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(calls.length, 2);
    assert.match(String(calls[0]?.[0]), /\/bot123456:secret-token\/getFile/);
    assert.match(String(calls[1]?.[0]), /\/file\/bot123456:secret-token\/documents\/file_42\.bin/);
  });

  for (
    const kind of [
      "missing",
      "malformed",
      "expired",
      "future",
      "wrong issuer",
      "wrong audience",
      "wrong signature",
      "excessive lifetime",
    ] as const
  ) {
    it(`rejects ${kind} grants without contacting Telegram`, async () => {
      const calls: unknown[][] = [];
      globalThis.fetch = mockFetch(calls, []);
      let token: string | undefined;
      if (kind === "malformed") token = "not-a-jwt";
      if (kind === "expired") token = await grant({ iat: 100, exp: 200 }, 300);
      if (kind === "future") token = await grant({ iat: 1_100, exp: 1_200 }, 1_000);
      if (kind === "wrong issuer") token = await grant({ iss: "other" });
      if (kind === "wrong audience") token = await grant({ aud: "other" });
      if (kind === "wrong signature") token = `${await grant()}broken`;
      if (kind === "excessive lifetime") token = await grant({ exp: Math.floor(Date.now() / 1000) + 301 });
      const response = await invoke("/v1/file", token);
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { ok: false, error: { code: "invalid_grant" } });
      assert.equal(calls.length, 0);
    });
  }

  it("rejects unsupported JWT algorithms", async () => {
    const token = await grant({}, undefined, { alg: "none", typ: "JWT" });
    const response = await invoke("/v1/file", token);
    assert.equal(response.status, 401);
  });

  it("rejects an oversized Telegram file before requesting its body", async () => {
    const calls: unknown[][] = [];
    globalThis.fetch = mockFetch(calls, [
      new Response(JSON.stringify({
        ok: true,
        result: { file_size: 20 * 1024 * 1024 + 1, file_path: "large.bin" },
      }), { status: 200 }),
    ]);
    const response = await invoke("/v1/file", await grant());
    assert.equal(response.status, 413);
    assert.equal(calls.length, 1);
  });

  it("rejects an oversized upstream response before streaming it", async () => {
    const calls: unknown[][] = [];
    globalThis.fetch = mockFetch(calls, [
      new Response(JSON.stringify({
        ok: true,
        result: { file_path: "large.bin" },
      }), { status: 200 }),
      new Response("not actually large", {
        status: 200,
        headers: { "content-length": String(20 * 1024 * 1024 + 1) },
      }),
    ]);
    const response = await invoke("/v1/file", await grant());
    assert.equal(response.status, 413);
    assert.deepEqual(await response.json(), { ok: false, error: { code: "file_too_large" } });
    assert.equal(calls.length, 2);
  });

  it("sanitizes Telegram failures", async () => {
    globalThis.fetch = mockFetch([], [
      new Response(JSON.stringify({
        ok: false,
        description: "token 123456:secret-token failed",
      }), { status: 400 }),
    ]);
    const response = await invoke("/v1/file", await grant());
    assert.equal(response.status, 502);
    assert.equal(await response.text(), '{"ok":false,"error":{"code":"telegram_rejected_file"}}');
  });

  it("maps unavailable file bodies to a sanitized stable error", async () => {
    const token = await grant();
    globalThis.fetch = mockFetch([], [
      new Response(JSON.stringify({
        ok: true,
        result: { file_size: 10, file_path: "documents/secret-path.bin" },
      }), { status: 200 }),
      new Response(`token ${env.TELEGRAM_BOT_TOKEN} path documents/secret-path.bin`, { status: 404 }),
    ]);
    const response = await invoke("/v1/file", token);
    assert.equal(response.status, 502);
    const text = await response.text();
    assert.equal(text, '{"ok":false,"error":{"code":"file_unavailable"}}');
    assert.doesNotMatch(text, new RegExp(env.TELEGRAM_BOT_TOKEN));
    assert.doesNotMatch(text, /secret-path|Bearer|eyJ/);
  });

  it("does not accept arbitrary routes or methods", async () => {
    assert.equal((await invoke("/v1/file", undefined, "POST")).status, 405);
    assert.equal((await invoke("/v1/file/https://example.com")).status, 404);
  });
});

function mockFetch(calls: unknown[][], responses: Response[]): typeof fetch {
  return (async (...args: Parameters<typeof fetch>) => {
    calls.push(args);
    const response = responses.shift();
    if (!response) throw new Error("unexpected fetch");
    return response;
  }) as typeof fetch;
}

async function invoke(path: string, token?: string, method = "GET"): Promise<Response> {
  const init: RequestInit = { method };
  if (token) init.headers = { authorization: `Bearer ${token}` };
  const request = (
    new Request(`https://gateway.test${path}`, init)
  ) as unknown as Request<unknown, IncomingRequestCfProperties>;
  return worker.fetch(request, env);
}

async function grant(
  overrides: Record<string, unknown> = {},
  now = Math.floor(Date.now() / 1000),
  header: Record<string, unknown> = { alg: "HS256", typ: "JWT" },
): Promise<string> {
  const encodedHeader = encode(header);
  const encodedPayload = encode({
    iss: env.FILE_GRANT_ISSUER,
    aud: env.FILE_GRANT_AUDIENCE,
    iat: now,
    exp: now + 300,
    jti: "12345678-1234-1234-1234-123456789abc",
    telegram_file_id: "BQAC-test-file",
    max_bytes: 20 * 1024 * 1024,
    ...overrides,
  });
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64Url(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
  );
  return `${encodedHeader}.${encodedPayload}.${encodeBytes(new Uint8Array(signature))}`;
}

function encode(value: unknown): string {
  return encodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function encodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(44, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
