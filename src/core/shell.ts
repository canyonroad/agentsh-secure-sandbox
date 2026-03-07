/**
 * Shell escape utility for safe command construction.
 *
 * Joins a command and its arguments into a single shell-safe string.
 * Args containing shell metacharacters or spaces are wrapped in single quotes,
 * with internal single quotes escaped as `'\''`.
 */

/** A string is "safe" (no quoting needed) if it matches this pattern. */
const SAFE_ARG = /^[a-zA-Z0-9._\-\/=:@]+$/;

export function shellEscape(cmd: string, args?: string[]): string {
  if (!args || args.length === 0) return cmd;
  const escaped = args.map((arg) => {
    if (SAFE_ARG.test(arg)) return arg;
    return "'" + arg.replace(/'/g, "'\\''") + "'";
  });
  return [cmd, ...escaped].join(' ');
}
