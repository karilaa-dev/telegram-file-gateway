import { MAX_FILE_BYTES, verifyFileGrant } from "./grant";

export interface Env {
  TELEGRAM_BOT_TOKEN: string;
  FILE_GRANT_HMAC_KEY: string;
  FILE_GRANT_ISSUER: string;
  FILE_GRANT_AUDIENCE: string;
}

type TelegramGetFileResponse = {
  ok?: boolean;
  result?: {
    file_size?: number;
    file_path?: string;
  };
};

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return json({ ok: true, service: "telegram-file-gateway" }, 200);
    }
    if (url.pathname !== "/v1/file") return jsonError("not_found", 404);
    if (request.method !== "GET") return jsonError("method_not_allowed", 405, { Allow: "GET" });

    const authorization = request.headers.get("authorization");
    const match = authorization?.match(/^Bearer ([A-Za-z0-9._-]+)$/);
    if (!match?.[1]) return jsonError("invalid_grant", 401);

    let grant;
    try {
      grant = await verifyFileGrant(match[1], {
        key: env.FILE_GRANT_HMAC_KEY,
        issuer: env.FILE_GRANT_ISSUER,
        audience: env.FILE_GRANT_AUDIENCE,
      });
    } catch (error) {
      if (/configuration/i.test(String(error))) return jsonError("gateway_misconfigured", 503);
      return jsonError("invalid_grant", 401);
    }

    const maximumBytes = Math.min(grant.max_bytes, MAX_FILE_BYTES);
    const getFileUrl = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getFile`;
    let metadataResponse: Response;
    try {
      metadataResponse = await fetch(getFileUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ file_id: grant.telegram_file_id }),
        redirect: "error",
      });
    } catch {
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
        { redirect: "error" },
      );
    } catch {
      return jsonError("telegram_unavailable", 502);
    }
    if (!fileResponse.ok || !fileResponse.body) {
      return jsonError(fileResponse.status === 404 ? "file_unavailable" : "telegram_unavailable", 502);
    }

    const contentLength = parseContentLength(fileResponse.headers.get("content-length"));
    if (contentLength !== null && contentLength > maximumBytes) return jsonError("file_too_large", 413);

    const headers = new Headers({
      "cache-control": "no-store",
      "content-type": fileResponse.headers.get("content-type") || "application/octet-stream",
      "x-content-type-options": "nosniff",
    });
    if (contentLength !== null) headers.set("content-length", String(contentLength));
    return new Response(limitStream(fileResponse.body, maximumBytes), { status: 200, headers });
  },
} satisfies ExportedHandler<Env>;

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
