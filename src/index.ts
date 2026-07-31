import {
  MAX_FILE_BYTES,
  type TelegramSendGrantV1,
  verifyFileGrant,
  verifySendGrant,
} from "./grant";

type TelegramGetFileResponse = {
  ok?: boolean;
  result?: {
    file_size?: number;
    file_path?: string;
  };
};

type TelegramPhotoSize = {
  file_id?: string;
  file_unique_id?: string;
  width?: number;
  height?: number;
  file_size?: number;
};

type TelegramSentMessage = {
  message_id?: number;
  document?: {
    file_id?: string;
    file_unique_id?: string;
    file_name?: string;
    mime_type?: string;
    file_size?: number;
  };
  photo?: TelegramPhotoSize[];
};

type TelegramSendResponse = {
  ok?: boolean;
  result?: TelegramSentMessage;
};

const TELEGRAM_RESPONSE_LIMIT = 128 * 1024;

export default {
  fetch: handleRequest,
} satisfies ExportedHandler<Env>;

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/healthz") {
    return json({ ok: true, service: "telegram-file-gateway" }, 200);
  }
  if (url.pathname === "/v1/file") return handleDownload(request, env);
  if (url.pathname === "/v1/send") return handleSend(request, env);
  return jsonError("not_found", 404);
}

async function handleDownload(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return jsonError("method_not_allowed", 405, { Allow: "GET" });
  const token = bearerToken(request);
  if (!token) return jsonError("invalid_grant", 401);

  let grant;
  try {
    grant = await verifyFileGrant(token, grantConfiguration(env));
  } catch (error) {
    if (/configuration/i.test(String(error))) return jsonError("gateway_misconfigured", 503);
    return jsonError("invalid_grant", 401);
  }

  const maximumBytes = Math.min(grant.max_bytes, MAX_FILE_BYTES);
  let metadataResponse: Response;
  try {
    metadataResponse = await fetch(telegramMethodUrl(env, "getFile"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ file_id: grant.telegram_file_id }),
      redirect: "follow",
    });
  } catch (error) {
    logFetchFailure("metadata", error);
    return jsonError("telegram_unavailable", 502);
  }

  let metadata: TelegramGetFileResponse;
  try {
    metadata = await metadataResponse.json<TelegramGetFileResponse>();
  } catch {
    return jsonError("telegram_invalid_response", 502);
  }
  if (!metadataResponse.ok || metadata.ok !== true || !metadata.result) {
    return jsonError(metadataResponse.status === 404 ? "file_unavailable" : "telegram_rejected_file", 502);
  }
  if (
    typeof metadata.result.file_size === "number"
    && (
      !Number.isSafeInteger(metadata.result.file_size)
      || metadata.result.file_size < 0
      || metadata.result.file_size > maximumBytes
    )
  ) {
    return metadata.result.file_size > maximumBytes
      ? jsonError("file_too_large", 413)
      : jsonError("telegram_invalid_response", 502);
  }
  const filePath = metadata.result.file_path;
  if (!isSafeTelegramPath(filePath)) return jsonError("telegram_invalid_response", 502);

  let fileResponse: Response;
  try {
    fileResponse = await fetch(
      `https://api.telegram.org/file/bot${env.TELEGRAM_BOT_TOKEN}/${filePath}`,
      { redirect: "follow" },
    );
  } catch (error) {
    logFetchFailure("file", error);
    return jsonError("telegram_unavailable", 502);
  }
  if (!fileResponse.ok || !fileResponse.body) {
    const code = fileResponse.status === 404
      ? "file_unavailable"
      : fileResponse.status === 401 || fileResponse.status === 403
        ? "telegram_rejected_file"
        : fileResponse.status === 429
          ? "telegram_rate_limited"
          : "telegram_unavailable";
    return jsonError(code, 502);
  }

  const contentLength = parseContentLength(fileResponse.headers.get("content-length"));
  if (contentLength !== null && contentLength > maximumBytes) return jsonError("file_too_large", 413);

  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": fileResponse.headers.get("content-type") || "application/octet-stream",
    "x-content-type-options": "nosniff",
  });
  return new Response(limitStream(fileResponse.body, maximumBytes), { status: 200, headers });
}

async function handleSend(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return jsonError("method_not_allowed", 405, { Allow: "POST" });
  const token = bearerToken(request);
  if (!token) return jsonError("invalid_grant", 401);

  let grant: TelegramSendGrantV1;
  try {
    grant = await verifySendGrant(token, grantConfiguration(env));
  } catch (error) {
    if (/configuration/i.test(String(error))) return jsonError("gateway_misconfigured", 503);
    return jsonError("invalid_grant", 401);
  }
  if (!request.body) return jsonError("invalid_file_body", 400);
  if (request.headers.get("content-encoding")) return jsonError("invalid_file_body", 400);
  if (request.headers.get("content-type")?.toLowerCase() !== "application/octet-stream") {
    return jsonError("invalid_file_body", 400);
  }
  const contentLength = parseContentLength(request.headers.get("content-length"));
  if (contentLength === null || contentLength !== grant.file_size) {
    return contentLength !== null && contentLength > grant.max_bytes
      ? jsonError("file_too_large", 413)
      : jsonError("invalid_file_body", 400);
  }
  if (contentLength > Math.min(grant.max_bytes, MAX_FILE_BYTES)) return jsonError("file_too_large", 413);

  const multipart = createTelegramMultipart(request.body, grant);
  let telegramResponse: Response;
  try {
    [telegramResponse] = await Promise.all([
      fetch(telegramMethodUrl(env, grant.delivery === "photo" ? "sendPhoto" : "sendDocument"), {
        method: "POST",
        headers: {
          "content-type": `multipart/form-data; boundary=${multipart.boundary}`,
        },
        body: multipart.body,
        redirect: "follow",
      }),
      multipart.completed,
    ]);
  } catch (error) {
    logFetchFailure("send", error);
    return jsonError("telegram_unavailable", 502);
  }

  let sent: TelegramSendResponse;
  try {
    sent = JSON.parse(await readBoundedText(telegramResponse, TELEGRAM_RESPONSE_LIMIT)) as TelegramSendResponse;
  } catch {
    return jsonError("telegram_invalid_response", 502);
  }
  if (!telegramResponse.ok || sent.ok !== true || !isSentMessage(sent.result)) {
    const code = telegramResponse.status === 429
      ? "telegram_rate_limited"
      : telegramResponse.status === 401 || telegramResponse.status === 403
        ? "telegram_rejected_credentials"
        : telegramResponse.status >= 500
          ? "telegram_unavailable"
          : "telegram_rejected_file";
    return jsonError(code, code === "telegram_rate_limited" ? 429 : 502);
  }

  return json({
    ok: true,
    result: {
      message_id: sent.result.message_id,
      delivery: grant.delivery,
      ...(sent.result.document ? { document: normalizeDocument(sent.result.document) } : {}),
      ...(sent.result.photo ? { photo: sent.result.photo.map(normalizePhoto) } : {}),
    },
  }, 200);
}

function createTelegramMultipart(
  source: ReadableStream<Uint8Array>,
  grant: TelegramSendGrantV1,
): {
  boundary: string;
  body: ReadableStream<Uint8Array>;
  completed: Promise<void>;
} {
  const boundary = `telegram-file-gateway-${crypto.randomUUID()}`;
  const partName = grant.delivery === "photo" ? "photo" : "document";
  const fields = [
    multipartField(boundary, "chat_id", grant.telegram_chat_id),
    ...(grant.telegram_message_thread_id === null
      ? []
      : [multipartField(boundary, "message_thread_id", String(grant.telegram_message_thread_id))]),
    ...(grant.caption === null ? [] : [multipartField(boundary, "caption", grant.caption)]),
  ];
  const prefix = new TextEncoder().encode(
    `${fields.join("")}--${boundary}\r\n`
      + `Content-Disposition: form-data; name="${partName}"; filename="${asciiFileName(grant.file_name)}"; filename*=UTF-8''${encodeRfc5987(grant.file_name)}\r\n`
      + `Content-Type: ${grant.mime_type}\r\n\r\n`,
  );
  const suffix = new TextEncoder().encode(`\r\n--${boundary}--\r\n`);
  const length = prefix.byteLength + grant.file_size + suffix.byteLength;
  const stream = createFixedLengthStream(length);
  const completed = copyMultipart(stream.writable, source, prefix, suffix, grant.file_size);
  return { boundary, body: stream.readable, completed };
}

function createFixedLengthStream(length: number): {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
} {
  const Constructor = (globalThis as typeof globalThis & {
    FixedLengthStream?: new (length: number) => {
      readable: ReadableStream<Uint8Array>;
      writable: WritableStream<Uint8Array>;
    };
  }).FixedLengthStream;
  return Constructor ? new Constructor(length) : new TransformStream<Uint8Array, Uint8Array>();
}

async function copyMultipart(
  destination: WritableStream<Uint8Array>,
  source: ReadableStream<Uint8Array>,
  prefix: Uint8Array,
  suffix: Uint8Array,
  expectedSize: number,
): Promise<void> {
  const writer = destination.getWriter();
  const reader = source.getReader();
  let received = 0;
  try {
    await writer.write(prefix);
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      received += result.value.byteLength;
      if (received > expectedSize) throw new Error("request body exceeded signed size");
      await writer.write(result.value);
    }
    if (received !== expectedSize) throw new Error("request body did not match signed size");
    await writer.write(suffix);
    await writer.close();
  } catch (error) {
    await writer.abort(error).catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}

function multipartField(boundary: string, name: string, value: string): string {
  return `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;
}

function asciiFileName(value: string): string {
  const sanitized = value.replace(/[^\x20-\x7e]|["\\]/g, "_").slice(0, 120);
  return sanitized || "file";
}

function encodeRfc5987(value: string): string {
  return encodeURIComponent(value).replace(/['()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function bearerToken(request: Request): string | undefined {
  const match = request.headers.get("authorization")?.match(/^Bearer ([A-Za-z0-9._-]+)$/);
  return match?.[1];
}

function grantConfiguration(env: Env): { key: string; issuer: string; audience: string } {
  return {
    key: env.FILE_GRANT_HMAC_KEY,
    issuer: env.FILE_GRANT_ISSUER,
    audience: env.FILE_GRANT_AUDIENCE,
  };
}

function telegramMethodUrl(env: Env, method: string): string {
  return `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`;
}

function isSentMessage(value: TelegramSentMessage | undefined): value is TelegramSentMessage & { message_id: number } {
  return Boolean(value && Number.isSafeInteger(value.message_id) && (value.document || value.photo?.length));
}

function normalizeDocument(value: NonNullable<TelegramSentMessage["document"]>): Record<string, unknown> {
  return compact({
    file_id: stringOrUndefined(value.file_id),
    file_unique_id: stringOrUndefined(value.file_unique_id),
    file_name: stringOrUndefined(value.file_name),
    mime_type: stringOrUndefined(value.mime_type),
    file_size: nonNegativeIntegerOrUndefined(value.file_size),
  });
}

function normalizePhoto(value: TelegramPhotoSize): Record<string, unknown> {
  return compact({
    file_id: stringOrUndefined(value.file_id),
    file_unique_id: stringOrUndefined(value.file_unique_id),
    width: nonNegativeIntegerOrUndefined(value.width),
    height: nonNegativeIntegerOrUndefined(value.height),
    file_size: nonNegativeIntegerOrUndefined(value.file_size),
  });
}

function compact(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function nonNegativeIntegerOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) throw new Error("missing Telegram response body");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    received += result.value.byteLength;
    if (received > maximumBytes) {
      await reader.cancel();
      throw new Error("Telegram response exceeded maximum size");
    }
    text += decoder.decode(result.value, { stream: true });
  }
  return text + decoder.decode();
}

function json(value: unknown, status: number, extraHeaders: HeadersInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      ...Object.fromEntries(new Headers(extraHeaders)),
    },
  });
}

function jsonError(code: string, status: number, extraHeaders: HeadersInit = {}): Response {
  return json({ ok: false, error: { code } }, status, extraHeaders);
}

function isSafeTelegramPath(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 1024
    && !value.startsWith("/")
    && !value.includes("..")
    && !/[?#\\\0]/.test(value);
}

function parseContentLength(value: string | null): number | null {
  if (value === null || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function logFetchFailure(stage: "metadata" | "file" | "send", error: unknown): void {
  const message = error instanceof Error ? error.message : "";
  const reason = /\b1042\b|another Worker|same zone/i.test(message)
    ? "worker_fetch_blocked"
    : /redirect/i.test(message)
      ? "redirect_failed"
      : /network connection lost|dns|connect|socket|tls/i.test(message)
        ? "network_failed"
        : "fetch_failed";
  console.error(JSON.stringify({ event: "telegram_fetch_failed", stage, reason }));
}

function limitStream(source: ReadableStream<Uint8Array>, maximumBytes: number): ReadableStream<Uint8Array> {
  let received = 0;
  return source.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      received += chunk.byteLength;
      if (received > maximumBytes) {
        controller.error(new Error("upstream file exceeded signed size limit"));
        return;
      }
      controller.enqueue(chunk);
    },
  }));
}
