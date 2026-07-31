# Telegram File Gateway

A small Cloudflare Worker that lets trusted applications download and send
Telegram Bot API files without exposing the bot token to file clients.

Each Worker deployment serves one Telegram bot token. A trusted application
mints a short-lived, operation-specific HS256 grant. Download grants contain one
Telegram `file_id`. Send grants bind the exact chat, optional Telegram topic,
delivery mode, filename, MIME type, caption, and byte count. The Worker validates
the grant and streams bytes in either direction without buffering the file.

Telegram may redirect its own metadata and file requests. The Worker follows
those redirects internally; it never forwards a redirect or upstream location
header to the downloader.

## API

`GET /healthz` returns service health.

`GET /v1/file` requires `Authorization: Bearer <JWT>`. The HS256 JWT must contain:

```json
{
  "iss": "your-application",
  "aud": "telegram-file-gateway",
  "iat": 1785456000,
  "exp": 1785456300,
  "jti": "a-unique-random-value",
  "op": "download_file",
  "telegram_file_id": "BQAC...",
  "max_bytes": 20971520
}
```

The grant may live for at most five minutes. `max_bytes` cannot exceed 20 MiB,
which is also the standard Telegram Bot API download limit.

`POST /v1/send` accepts an exact-length `application/octet-stream` request body
and requires a send grant:

```json
{
  "iss": "your-application",
  "aud": "telegram-file-gateway",
  "iat": 1785456000,
  "exp": 1785456300,
  "jti": "a-unique-random-value",
  "op": "send_file",
  "telegram_chat_id": "-1001234567890",
  "telegram_message_thread_id": 42,
  "delivery": "document",
  "file_name": "report.pdf",
  "mime_type": "application/pdf",
  "caption": "Quarterly report",
  "file_size": 482013,
  "max_bytes": 20971520
}
```

The request `Content-Length` must equal the signed `file_size`. The Worker
constructs a streamed multipart request to Telegram's `sendDocument` or
`sendPhoto` method. It returns only the message and Telegram file identifiers
needed for durable reference tracking. The client cannot change the destination,
topic, media method, metadata, or size without invalidating the signature.

## Local development

```sh
npm install
cp .dev.vars.example .dev.vars
npm run dev
```

Never commit `.dev.vars` or any `.env` file. Generate a signing key with:

```sh
node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url") + "\\n")'
```

Configure the same key in the trusted grant issuer. `examples/sign-grant.ts`
and `examples/sign-send-grant.ts` show dependency-free Node.js signers.

## Test and build

```sh
npm run typecheck
npm test
npm run test:workers
npm run build
```

The fast protocol suite runs in Node with mocked Telegram responses, and the
Worker smoke suite runs in Cloudflare's Vitest pool.

After changing bindings or compatibility flags, regenerate the checked-in
runtime and binding declarations:

```sh
npm run types
```

## Deploy

For an interactive production deployment:

```sh
npx wrangler login
npx wrangler deploy \
  --secrets-file /path/to/a/temporary-secrets-file \
  --var FILE_GRANT_ISSUER:your-application \
  --var FILE_GRANT_AUDIENCE:telegram-file-gateway
```

The temporary secrets file contains:

```dotenv
TELEGRAM_BOT_TOKEN=123456:...
FILE_GRANT_HMAC_KEY=...
```

Create it outside the repository with mode `0600` and remove it immediately
after deployment. The required secret names are declared in `wrangler.jsonc`;
secret values are never committed.

Set `FILE_GRANT_ISSUER` to the stable identifier of the application that mints
grants. Wrangler command-line variables override the generic values in
`wrangler.jsonc`; keep the same values in the grant issuer's configuration.

For CI deployments, use Cloudflare's official Wrangler GitHub Action with a
narrowly scoped `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Do not put
either value in workflow source.

## Security model

- There is no arbitrary upstream URL or Telegram destination input outside a
  signed grant.
- The Telegram bot token never appears in a response, redirect, grant, or log.
- Grants are restricted to one operation, one file or destination, one issuer,
  one audience, and five minutes.
- Upload bodies must have the exact signed length, and send metadata is never
  accepted from query parameters or unsigned headers.
- Responses are not cached and CORS is not enabled.
- Rotate the HMAC key by updating the Worker secret and every trusted issuer
  together. Existing grants become invalid immediately.
