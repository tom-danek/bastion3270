// What the user is told when the gateway reports an error or ends a session, and how a lost
// connection is retried.
//
// Pure: no DOM access, so it can be tested in any browser by importing the module.

/** Close reasons with their own text (`closed.<reason>` in i18n.js). */
const CLOSE_REASONS = new Set([
  "user", "server_shutdown", "host_disconnected", "rate_limited", "handshake_timeout",
  "shutting_down", "idle", "lifetime", "identity_expired", "ended",
]);

/** Error codes with their own text (`error.<code>` in i18n.js). */
const ERROR_CODES = new Set([
  "unknown_profile", "forbidden", "limit_exceeded", "auth_failed", "connect_failed",
  "store_failed", "internal_error", "session_not_found", "shutting_down", "paste_too_long",
  "dlp_denied", "input_held", "bad_request", "invalid_options", "print_denied",
]);

/**
 * The message for a `closed` message of the gateway.
 *
 * * `level`: `info` (expected, e.g. the user disconnected) or `warn`;
 * * `again`: offer "Connect again" with the same profile (the user did not choose to leave);
 * * `key` / `params`: the text (i18n.js).
 *
 * @param {string} reason
 * @returns {{key: string, params: Record<string, string>, level: "info"|"warn", again: boolean}}
 */
export function closedMessage(reason) {
  if (reason === "user") return { key: "closed.user", params: {}, level: "info", again: false };
  const key = CLOSE_REASONS.has(reason) ? "closed." + reason : "closed.other";
  return { key, params: { reason }, level: "warn", again: true };
}

/**
 * The message for an `error` message of the gateway. Errors while opening a session are
 * `error` level; refused input (paste, held input) only `warn`.
 *
 * @param {string} code
 * @param {string} message  the gateway's English text, shown for unknown codes
 * @returns {{key: string, params: Record<string, string>, level: "warn"|"error"}}
 */
export function errorMessage(code, message) {
  const key = ERROR_CODES.has(code) ? "error." + code : "error.other";
  const input = code === "paste_too_long" || code === "dlp_denied" || code === "input_held";
  return { key, params: { message: String(message || code) }, level: input ? "warn" : "error" };
}

/**
 * Delay before reconnect attempt `attempt` (1, 2, …): 1 s, 2 s, 4 s, 8 s, then every 15 s.
 * `null` once the next attempt would start after `graceSecs` (the gateway has ended the
 * detached session by then, so resuming cannot succeed).
 *
 * @param {number} attempt
 * @param {number} elapsedMs  time since the connection was lost
 * @param {number} graceSecs  the gateway's `resume_grace_secs`
 */
export function reconnectDelay(attempt, elapsedMs, graceSecs) {
  const delay = Math.min(1000 * 2 ** Math.max(0, attempt - 1), 15000);
  return elapsedMs + delay > graceSecs * 1000 ? null : delay;
}
