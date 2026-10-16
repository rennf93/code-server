import * as http from "http"
import { setDefaults, parse } from "../../../src/node/cli"
import { guardConfig } from "../../../src/node/guard"
import { mockLogger } from "../../utils/helpers"
import * as httpserver from "../../utils/httpserver"
import * as integration from "../../utils/integration"

describe("guard", () => {
  let codeServer: httpserver.HttpServer | undefined
  const previousEnvPassword = process.env.PASSWORD

  beforeAll(() => {
    mockLogger()
  })

  afterEach(async () => {
    process.env.PASSWORD = previousEnvPassword
    if (codeServer) {
      await codeServer.dispose()
      codeServer = undefined
    }
    jest.resetModules()
  })

  describe("disabled", () => {
    it("should not load the package or screen requests", async () => {
      // Requiring the package would throw, so serving requests proves it is never loaded.
      jest.doMock("@guardcore/express", () => {
        throw new Error("@guardcore/express must not be loaded when --guard is unset")
      })
      codeServer = await integration.setup(["--auth=none"], "")
      // Well over the guard rate limit and with an obvious attack string.
      for (let i = 0; i < 5; i++) {
        const resp = await codeServer.fetch("/healthz", {}, { q: "' UNION SELECT password FROM users--" })
        expect(resp.status).toBe(200)
      }
      jest.dontMock("@guardcore/express")
    })
  })

  describe("config", () => {
    it("should default to loopback proxies and no allowlist", async () => {
      const args = await setDefaults(parse(["--guard"]))
      const config = guardConfig(args)
      expect(config.trustedProxies).toEqual(["127.0.0.1", "::1"])
      expect(config.whitelist).toBeNull()
      expect(config.rateLimit).toBe(1200)
      expect(config.enableRedis).toBe(false)
    })
  })

  describe("enabled", () => {
    const get = (path: string, headers: http.OutgoingHttpHeaders = {}) =>
      codeServer!.fetch(path, { headers: headers as Record<string, string> })

    it("should return 429 once the rate limit is exceeded", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard", "--guard-rate-limit=5"], "")
      const statuses: number[] = []
      for (let i = 0; i < 8; i++) {
        statuses.push((await get("/robots.txt")).status)
      }
      expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200])
      expect(statuses).toContain(429)
    })

    it("should return 403 for IPs outside the allowlist", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard", "--guard-allow-ip=203.0.113.9"], "")
      expect((await get("/robots.txt")).status).toBe(403)
    })

    it("should allow IPs on the allowlist", async () => {
      codeServer = await integration.setup(
        ["--auth=none", "--guard", "--guard-allow-ip=127.0.0.1", "--guard-allow-ip=::1"],
        "",
      )
      expect((await get("/robots.txt")).status).toBe(200)
    })

    it("should trust X-Forwarded-For from a loopback proxy by default", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard", "--guard-allow-ip=203.0.113.9"], "")
      expect((await get("/robots.txt", { "x-forwarded-for": "203.0.113.9" })).status).toBe(200)
      expect((await get("/robots.txt", { "x-forwarded-for": "198.51.100.7" })).status).toBe(403)
    })

    it("should ignore a spoofed X-Forwarded-For from an untrusted peer", async () => {
      // Loopback is not a trusted proxy here, so the header must be ignored.
      codeServer = await integration.setup(
        ["--auth=none", "--guard", "--guard-allow-ip=203.0.113.9", "--guard-trusted-proxy=10.0.0.0/8"],
        "",
      )
      expect((await get("/robots.txt", { "x-forwarded-for": "203.0.113.9" })).status).toBe(403)
    })

    it("should block an attack in the query string", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard"], "")
      const resp = await codeServer.fetch("/robots.txt", {}, { q: "' UNION SELECT password FROM users--" })
      expect(resp.status).toBe(400)
      expect(await resp.text()).toContain("Suspicious")
      expect((await get("/robots.txt")).status).toBe(200)
    })

    it("should not scan request bodies", async () => {
      process.env.PASSWORD = "test"
      codeServer = await integration.setup(["--auth=password", "--guard"], "")
      const params = new URLSearchParams()
      params.append("password", "' UNION SELECT password FROM users--")
      const resp = await codeServer.fetch("/login", { method: "POST", body: params })
      expect(resp.status).toBe(200)
      expect(await resp.text()).toContain("Incorrect password")
    })

    it("should serve the login page and leave the login limiter in place", async () => {
      process.env.PASSWORD = "test"
      codeServer = await integration.setup(["--auth=password", "--guard"], "")
      const resp = await codeServer.fetch("/login")
      expect(resp.status).toBe(200)
      expect(await resp.text()).toContain("Welcome")
      // The login limiter allows 14 attempts and is unaffected by the guard.
      const params = new URLSearchParams({ password: "wrong" })
      let last = ""
      for (let i = 0; i < 16; i++) {
        last = await (await codeServer.fetch("/login", { method: "POST", body: params })).text()
      }
      expect(last).toContain("Login rate limited!")
    })

    it("should serve static files and VS Code style paths", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard"], "")
      expect((await get("/_static/src/browser/robots.txt")).status).toBe(200)
      // A path shaped like the VS Code extension and static routes is not an attack.
      const resp = await get("/stable-0123456789abcdef/static/extensions/theme-defaults/package.json")
      expect(resp.status).not.toBe(403)
    })

    it("should not affect websocket upgrades", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard"], "")
      const ws = await codeServer.wsWait("/healthz")
      ws.terminate()
    })

    it("should reject websocket upgrades from IPs outside the allowlist", async () => {
      codeServer = await integration.setup(["--auth=none", "--guard", "--guard-allow-ip=203.0.113.9"], "")
      await expect(codeServer.wsWait("/healthz")).rejects.toThrow(/403/)
    })
  })
})
