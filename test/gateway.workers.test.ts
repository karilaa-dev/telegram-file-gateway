import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Workers runtime", () => {
  it("runs the health endpoint inside workerd", async () => {
    const response = await SELF.fetch("https://gateway.test/healthz");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      service: "telegram-file-gateway",
    });
  });
});
