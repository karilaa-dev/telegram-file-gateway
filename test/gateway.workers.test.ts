import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";

const env: Env = {
  TELEGRAM_BOT_TOKEN: "unused",
  FILE_GRANT_HMAC_KEY: "A".repeat(43),
  FILE_GRANT_ISSUER: "test",
  FILE_GRANT_AUDIENCE: "telegram-file-gateway",
};

describe("Workers runtime", () => {
  it("runs the health endpoint inside workerd", async () => {
    const request = (
      new Request("https://gateway.test/healthz")
    ) as unknown as Request<unknown, IncomingRequestCfProperties>;
    const response = await worker.fetch(request, env);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      service: "telegram-file-gateway",
    });
  });
});
