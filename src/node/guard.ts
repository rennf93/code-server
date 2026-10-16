import { logger } from "@coder/logger"
import type { SecurityConfig } from "@guardcore/express"
import { App } from "./app"
import { DefaultedArgs } from "./cli"

const DEFAULT_RATE_LIMIT = 1200
const DEFAULT_TRUSTED_PROXIES = ["127.0.0.1", "::1"]

/**
 * Build the Guard Core configuration from the CLI arguments.
 *
 * Only what is needed for opt-in request screening is enabled: there is no
 * Redis (state is per process, like the login limiter), no response header
 * changes (VS Code sets its own CSP), and request bodies are never scanned
 * because code-server does not buffer them for the guard.
 */
export const guardConfig = (args: DefaultedArgs): SecurityConfig => {
  const allow = args["guard-allow-ip"] || []
  return {
    enableRedis: false,
    whitelist: allow.length > 0 ? allow : null,
    rateLimit: args["guard-rate-limit"] || DEFAULT_RATE_LIMIT,
    rateLimitWindow: 60,
    // X-Forwarded-For is only honored when the direct peer is one of these.
    trustedProxies: args["guard-trusted-proxy"]?.length ? args["guard-trusted-proxy"] : DEFAULT_TRUSTED_PROXIES,
    securityHeaders: { enabled: false },
    logger: {
      info: (message) => logger.debug(message),
      warn: (message) => logger.warn(message),
      error: (message) => logger.error(message),
      debug: (message) => logger.debug(message),
    },
  }
}

/**
 * Register Guard Core on the HTTP router and on websocket upgrades.
 *
 * The package is imported here and nowhere else so it is never loaded unless
 * --guard is set. The HTTP middleware is added before every other middleware
 * so rejected requests do not reach the heartbeat, the static files or the
 * login limiter. Upgrades never go through the router middleware (their
 * response is not a real HTTP response), so the same checks run through the
 * upgrade hook instead; this is what makes the allowlist, bans and rate limit
 * apply to the VS Code and proxy websockets as well.
 */
export const registerGuard = async (app: App, args: DefaultedArgs): Promise<void> => {
  if (!args.guard) {
    return
  }
  const { createSecurityMiddleware, attachWebSocketGuard } = await import("@guardcore/express")
  const config = guardConfig(args)
  app.router.use(createSecurityMiddleware({ config }))
  attachWebSocketGuard(app.server, { config })
}
