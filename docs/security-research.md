# Security Research

Documented attacks with CVEs across major AI coding tools. This is the evidence base behind the `@agentsh/secure-sandbox` [default policy](default-policy.md).

## CVE & Attack Table

| Attack | CVE / Source | Tool |
|--------|-------------|------|
| Command injection via `.env` files | [CVE-2025-61260](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/) | Codex CLI |
| Secret exfiltration via serialization injection | [CVE-2025-68664](https://cyata.ai/blog/langgrinch-langchain-core-cve-2025-68664/) | LangChain |
| RCE via MCP config rewrite | [CVE-2025-54135](https://www.aim.security/post/when-public-prompts-turn-into-local-shells-rce-in-cursor-via-mcp-auto-start) | Cursor |
| RCE via prompt injection in repo comments | [CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) | Copilot |
| API key exfiltration via env var override | [CVE-2026-21852](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) | Claude Code |
| RCE via hook config in untrusted repo | [CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) | Claude Code |
| Command injection bypass of allowlist | [CVE-2025-54795](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/) | Claude Code |
| Sandbox escape via symlink traversal | [CVE-2025-53109](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/) | MCP Filesystem |
| Silent MCP server swap after approval | [CVE-2025-54136](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/) | Cursor |
| Case-sensitivity bypass of file protection | [CVE-2025-59944](https://www.lakera.ai/blog/cursor-vulnerability-cve-2025-59944) | Cursor |
| Sandbox bypass + C2 installation | [Embrace The Red](https://embracethered.com/blog/posts/2025/devin-i-spent-usd500-to-hack-devin/) | Devin |
| 30+ prompt injection to RCE across IDEs | [IDEsaster](https://maccarita.com/posts/idesaster/) | Cursor, Copilot, Windsurf, Roo, Junie |
| Prompt injection to RCE pipeline | [Trail of Bits](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/) | Multiple |
| Cross-agent privilege escalation loop | [Embrace The Red](https://embracethered.com/blog/posts/2025/cross-agent-privilege-escalation-agents-that-free-each-other/) | Copilot + Claude |

## Policy Rules — Detailed Rationale

The sections below explain every rule in the default policy, the specific attack it prevents, and relevant security research. For the policy source code and extension API, see the [default policy documentation](default-policy.md).

### File Rules

#### Allow workspace read/write/create

```
{ allow: '/workspace/**', ops: ['read', 'write', 'create'] }
```

The agent can read, write, and create files anywhere under `/workspace/`. Delete operations are not included — agents cannot remove files, only create and modify them.

#### Deny secrets and credential files

```
{ deny: ['**/.env', '**/.env.*', '**/credentials*', '**/*.pem', '**/*.key'] }
```

`.env` files are the most common way developers store API keys, database URLs, and other secrets. PEM and key files contain TLS certificates and private keys. These are the #1 exfiltration target for hijacked agents.

- [CVE-2025-61260](https://nvd.nist.gov/vuln/detail/CVE-2025-61260) — OpenAI Codex CLI command injection via `.env` files
- [CVE-2025-68664 (LangGrinch)](https://cyata.ai/blog/langgrinch-langchain-core-cve-2025-68664/) — LangChain Core secret exfiltration via `secrets_from_env`
- [Trend Micro — AI Agent Vulnerabilities Part III: Data Exfiltration](https://www.trendmicro.com/vinfo/us/security/news/threat-landscape/unveiling-ai-agent-vulnerabilities-part-iii-data-exfiltration)

#### Deny git credentials

```
{ deny: ['/workspace/.git/config', '/workspace/.netrc'] }
```

`.git/config` can contain repository credentials (inline `https://token@github.com/...` URLs). `.netrc` stores plaintext credentials used by git, curl, and other tools.

- [Trail of Bits — Prompt Injection to RCE in AI Agents](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/) (Oct 2025)
- [GitGuardian — The State of Secrets Sprawl 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/)

#### Deny SSH keys and process environment

```
{ deny: ['~/.ssh/**', '/proc/*/environ'] }
```

SSH keys enable lateral movement — an agent with access to `~/.ssh/id_rsa` could push code to any repository the user has access to, or SSH into production servers. `/proc/*/environ` exposes every environment variable of every running process, including secrets passed via `docker run -e SECRET=...`.

- [Anthropic — Making Claude Code More Secure and Autonomous](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [CVE-2025-31133, CVE-2025-52565](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities) — runC vulnerabilities bypassing maskedPaths protections on `/proc`

#### Deny cloud provider credentials

```
{ deny: ['~/.aws/**', '~/.gcp/**', '~/.azure/**', '~/.config/gcloud/**'] }
```

Cloud credential files grant access to cloud infrastructure. A compromised agent could spin up crypto mining instances, access S3 buckets, or delete production resources.

- [CVE-2023-36052 (LeakyCLI)](https://orca.security/resources/blog/leakycli-aws-google-cloud-command-line-tools-can-expose-sensitive-credentials-build-logs/) — AWS and Google Cloud CLIs expose credentials in build logs
- [Google Cloud Threat Horizons Report H2 2025](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h2-2025)

#### Deny shell config files

```
{ deny: ['~/.bashrc', '~/.zshrc', '~/.profile', '~/.bash_profile'] }
```

Shell configuration files execute on every new shell session. An agent that writes to `~/.bashrc` can establish persistence.

- [MITRE ATT&CK T1546.004 — Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004/)
- [Elastic Security Labs — Linux Persistence Mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

#### Deny credential stores

```
{ deny: ['~/.gitconfig', '~/.netrc', '~/.curlrc', '~/.wgetrc'] }
```

`~/.gitconfig` can contain credential helpers and stored tokens. `~/.curlrc` and `~/.wgetrc` can be modified to route all HTTP traffic through an attacker-controlled proxy.

- [Exploit-DB 40064](https://www.exploit-db.com/exploits/40064) — GNU Wget `.wgetrc` injection
- [HackTricks — Exfiltration techniques via curl](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration)

#### Deny PATH hijacking

```
{ deny: '~/.local/bin/**' }
```

`~/.local/bin/` is typically at the front of `$PATH`. An agent that writes a malicious `git` or `npm` binary here can intercept all subsequent calls.

- [MITRE ATT&CK T1574.007 — Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007/)
- [CVE-2024-32019](https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC) — Netdata privilege escalation via PATH hijacking

#### Deny writes to agent config files

```
{ deny: ['**/.cursorrules', '**/CLAUDE.md', '**/copilot-instructions.md'], ops: ['write', 'create', 'delete'] }
```

Reads are allowed so the agent can follow project conventions. Writes are blocked because a compromised agent can rewrite these files to inject prompts that persist across sessions — the "Rules File Backdoor" attack.

- [CVE-2025-54135 (CurXecute)](https://nsfocusglobal.com/cursor-remote-code-execution-vulnerability-cve-2025-54135/) — Cursor RCE via config rewrite
- [CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) — GitHub Copilot RCE
- [Pillar Security — "Rules File Backdoor"](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [Trail of Bits — Prompt Injection Engineering for Attackers: Exploiting GitHub Copilot](https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/)

### Network Rules

#### Allow package registries on port 443

```
{ allow: ['registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org',
          'files.pythonhosted.org', 'crates.io', 'static.crates.io',
          'index.crates.io', 'proxy.golang.org', 'sum.golang.org',
          'github.com', 'raw.githubusercontent.com'], ports: [443] }
```

Agents need to install dependencies and access source code. Only HTTPS (port 443) is allowed.

#### Deny all other network

```
{ deny: '*' }
```

Default-deny prevents data exfiltration, reverse shells, DNS tunneling, and SSRF attacks against internal services.

- [NVIDIA — Practical Security Guidance for Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/)
- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)

### Command Rules

#### Allow safe commands

```
{ allow: ['bash', 'sh', 'echo', 'cat', 'head', 'tail', 'grep', 'find',
          'ls', 'wc', 'sort', 'uniq', 'diff', 'pwd', 'date', 'which',
          'whoami', 'id', 'uname', 'printf', 'test', 'true', 'false',
          'mkdir', 'cp', 'mv', 'rm', 'touch', 'chmod', 'tr', 'cut',
          'sed', 'awk', 'tee', 'xargs', 'basename', 'dirname', 'realpath',
          'base64', 'md5sum', 'sha256sum', 'tar', 'gzip', 'gunzip'] }
```

Standard Unix utilities needed for file manipulation, text processing, and build workflows.

#### Allow dev tools

```
{ allow: ['git', 'node', 'npm', 'npx', 'yarn', 'pnpm', 'bun',
          'python', 'python3', 'pip', 'pip3',
          'cargo', 'rustc', 'go', 'make', 'cmake'] }
```

Language runtimes and package managers needed for development workflows. Destructive git operations are separately denied.

#### Deny environment inspection

```
{ deny: ['env', 'printenv'] }
```

`env` and `printenv` dump all environment variables, which typically include API keys and secrets.

- [CVE-2024-10979](https://nvd.nist.gov/vuln/detail/CVE-2024-10979) — PostgreSQL environment variable exploitation (CVSS 8.8)

#### Deny privilege escalation

```
{ deny: ['sudo', 'su', 'doas'] }
```

- [CVE-2025-32463](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) — sudo privilege escalation to root via chroot option
- [HackTricks — Docker Breakout / Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)

#### Deny raw network tools

```
{ deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] }
```

These tools can establish reverse shells, giving an attacker interactive access to the sandbox.

- [Google Cloud SCC — Socat Reverse Shell Detected](https://cloud.google.com/security-command-center/docs/findings/threats/socat-reverse-shell-detected)
- [Wiz — Reverse Shell Attacks](https://www.wiz.io/academy/detection-and-response/reverse-shell-attacks)

#### Deny destructive git operations

```
{ deny: ['git push --force', 'git reset --hard'] }
```

- [Claude Code agent wiped production database via `--force` flag](https://github.com/anthropics/claude-code/issues/27063)
- [Destructive Command Guard](https://github.com/Dicklesworthstone/destructive_command_guard)

#### Redirect curl/wget through audited fetch

```
{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }
```

Instead of blocking HTTP clients outright, `curl` and `wget` are transparently redirected to `agentsh-fetch`, which enforces the network allowlist and logs all requests.

- [Elastic Security — Potential Data Exfiltration Through Curl](https://www.elastic.co/guide/en/security/8.19/potential-data-exfiltration-through-curl.html)

## Further Reading

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [IDEsaster — 30+ Vulnerabilities Across AI IDEs](https://maccarita.com/posts/idesaster/)
- [Trail of Bits — Prompt Injection to RCE in AI Agents](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)
- [Embrace The Red — Cross-Agent Privilege Escalation](https://embracethered.com/blog/posts/2025/cross-agent-privilege-escalation-agents-that-free-each-other/)
- [Check Point — RCE and API Token Exfiltration in Claude Code](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [NVIDIA — Practical Security Guidance for Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/)
- [Anthropic — Making Claude Code More Secure and Autonomous](https://www.anthropic.com/engineering/claude-code-sandboxing)
