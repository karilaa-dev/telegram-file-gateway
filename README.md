# Telegram File Gateway

A small Cloudflare Worker that lets trusted applications download files from the
Telegram Bot API without exposing the bot token to the downloader.

Each Worker deployment serves one Telegram bot token. A trusted application
mints a short-lived HS256 grant containing one Telegram `file_id`; the Worker
validates the grant and streams the file from Telegram without buffering or
redirecting the client to Telegram's token-bearing URL.

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
  "telegram_file_id": "BQAC...",
  "max_bytes": 20971520
}
```

The grant may live for at most five minutes. `max_bytes` cannot exceed 20 MiB,
which is also the standard Telegram Bot API download limit.

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
shows a dependency-free Node.js signer.

## Test and build

```sh
npm run typecheck
npm test
npm run test:workers
npm run build
```

The fast protocol suite runs in Node with mocked Telegram responses, and the
Worker smoke suite runs in Cloudflare's Vitest pool.

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

- There is no arbitrary upstream URL input.
- The Telegram bot token never appears in a response, redirect, grant, or log.
- Grants are restricted to one file, one issuer, one audience, and five minutes.
- Responses are not cached and CORS is not enabled.
- Rotate the HMAC key by updating the Worker secret and every trusted issuer
  together. Existing grants become invalid immediately.
