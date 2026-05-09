/**
 * Built-in agentsh mitigation set IDs that secure-sandbox knows about.
 *
 * Pass these to `seccompDetails.mitigationSets` instead of raw strings to
 * get autocomplete and a single update point when agentsh ships new
 * built-in mitigations.
 *
 * Reference: `internal/config/mitigations/` in canyonroad/agentsh.
 */
export const KNOWN_MITIGATIONS = {
  /**
   * Conservative mitigation for the Openwall Dirty Frag advisory dated
   * May 7 2026. Expands to two socket_rules: AF_RXRPC and
   * AF_NETLINK+NETLINK_XFRM, both with action `log_and_kill`.
   * Does NOT block all AF_NETLINK.
   */
  dirtyfragConservative: 'dirtyfrag-conservative',
} as const;

export type KnownMitigation =
  typeof KNOWN_MITIGATIONS[keyof typeof KNOWN_MITIGATIONS];
