/**
 * Shell escape utility for safe command construction.
 *
 * Joins a command and its arguments into a single shell-safe string.
 * Args containing shell metacharacters or spaces are wrapped in single quotes,
 * with internal single quotes escaped as `'\''`.
 */

/** A string is "safe" (no quoting needed) if it matches this pattern. */
const SAFE_ARG = /^[a-zA-Z0-9._\-\/=:@]+$/;

function quoteArg(arg: string): string {
  if (SAFE_ARG.test(arg)) return arg;
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

export function shellEscape(cmd: string, args?: string[]): string {
  if (!args || args.length === 0) return cmd;
  const escaped = args.map(quoteArg);
  return [cmd, ...escaped].join(' ');
}

/** Env key must be a valid shell identifier: letters, digits, underscores, starting with non-digit. */
const SAFE_ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Convert env vars to inline shell assignments prefix.
 * e.g. { TRACEPARENT: '00-abc-def-01' } → "TRACEPARENT='00-abc-def-01' "
 * Returns empty string if env is undefined or empty.
 * Keys that don't match a strict identifier pattern are silently skipped.
 */
export function envPrefix(env?: Record<string, string>): string {
  if (!env) return '';
  const parts: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    if (!SAFE_ENV_KEY.test(k)) continue;
    parts.push(`${k}=${quoteArg(v)}`);
  }
  if (parts.length === 0) return '';
  return parts.join(' ') + ' ';
}
