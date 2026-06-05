/**
 * blocklist.ts — CTF sandbox host extraction and blocklist enforcement.
 *
 * Default-deny for known sensitive ranges/TLDs; allowlist can override.
 * No external dependencies. Pure functions (except reading process.env once).
 */

export type BlocklistDecision =
  | { allowed: true }
  | { allowed: false; reason: string; host: string }

// ---------------------------------------------------------------------------
// CIDR helpers (IPv4 only)
// ---------------------------------------------------------------------------

function ipToInt(ip: string): number | null {
  const parts = ip.split(".")
  if (parts.length !== 4) return null
  let result = 0
  for (const part of parts) {
    const n = parseInt(part, 10)
    if (isNaN(n) || n < 0 || n > 255) return null
    result = (result << 8) | n
  }
  // Treat as unsigned 32-bit
  return result >>> 0
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/")
  if (slash === -1) return false
  const base = cidr.slice(0, slash)
  const bits = parseInt(cidr.slice(slash + 1), 10)
  if (isNaN(bits) || bits < 0 || bits > 32) return false

  const ipInt = ipToInt(ip)
  const baseInt = ipToInt(base)
  if (ipInt === null || baseInt === null) return false

  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ipInt & mask) === (baseInt & mask)
}

// ---------------------------------------------------------------------------
// Block rules
// ---------------------------------------------------------------------------

const BLOCKED_TLD_PATTERN = /\.(gov|mil)$/i

const BLOCKED_CIDRS: Array<{ cidr: string; reason: string }> = [
  { cidr: "10.0.0.0/8", reason: "RFC1918 private range" },
  { cidr: "172.16.0.0/12", reason: "RFC1918 private range" },
  { cidr: "192.168.0.0/16", reason: "RFC1918 private range" },
  { cidr: "127.0.0.0/8", reason: "loopback" },
  { cidr: "169.254.0.0/16", reason: "link-local" },
]

// ---------------------------------------------------------------------------
// Allowlist parsing
// ---------------------------------------------------------------------------

function parseAllowlist(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function isAllowed(host: string, entries: string[]): boolean {
  const lowerHost = host.toLowerCase()
  for (const entry of entries) {
    const lowerEntry = entry.toLowerCase()
    // Exact match
    if (lowerEntry === lowerHost) return true
    // Wildcard subdomain: *.example.com
    if (lowerEntry.startsWith("*.")) {
      const suffix = lowerEntry.slice(1) // ".example.com"
      if (lowerHost === suffix.slice(1) || lowerHost.endsWith(suffix)) return true
    }
    // Single IP exact
    if (lowerEntry === lowerHost) return true
    // CIDR
    if (lowerEntry.includes("/")) {
      if (ipInCidr(host, lowerEntry)) return true
    }
  }
  return false
}

// ---------------------------------------------------------------------------
// isBlocked
// ---------------------------------------------------------------------------

export function isBlocked(
  host: string,
  allowlist: string[],
): { blocked: boolean; reason?: string } {
  const lower = host.toLowerCase()

  // Check allowlist first
  if (allowlist.length > 0 && isAllowed(host, allowlist)) {
    return { blocked: false }
  }

  // Loopback hostname
  if (lower === "localhost" || lower === "::1") {
    return { blocked: true, reason: "loopback" }
  }

  // TLD check
  if (BLOCKED_TLD_PATTERN.test(lower)) {
    const tld = lower.match(/\.([a-z]+)$/i)?.[1] ?? ""
    return { blocked: true, reason: `.${tld} TLD is blocked` }
  }

  // IP-based checks
  for (const { cidr, reason } of BLOCKED_CIDRS) {
    if (ipInCidr(host, cidr)) {
      return { blocked: true, reason }
    }
  }

  return { blocked: false }
}

// ---------------------------------------------------------------------------
// Host extraction
// ---------------------------------------------------------------------------

const KNOWN_TOOLS = new Set([
  "nmap",
  "nikto",
  "gobuster",
  "dig",
  "host",
  "whois",
  "nc",
  "ncat",
  "ping",
  "traceroute",
  "dnsenum",
  "wfuzz",
  "dirb",
  "whatweb",
  "sqlmap",
])

const URL_RE = /https?:\/\/([^/\s:?#]+)/gi

export function extractHosts(command: string): string[] {
  const hosts: string[] = []
  const seen = new Set<string>()

  const add = (h: string) => {
    if (h && !seen.has(h)) {
      seen.add(h)
      hosts.push(h)
    }
  }

  // 1. URL-like tokens
  let m: RegExpExecArray | null
  URL_RE.lastIndex = 0
  while ((m = URL_RE.exec(command)) !== null) {
    add(m[1])
  }

  // 2. -u <host> or -u=<host> (curl-style)
  const uFlag = command.match(/-u[= ]([^\s]+)/)
  if (uFlag) {
    const val = uFlag[1]
    // might be a URL
    const inner = val.match(/^https?:\/\/([^/\s:?#]+)/)
    add(inner ? inner[1] : val)
  }

  // 3. -h <host> (nikto-style) — only if next token doesn't look like a flag
  const hFlagMatch = command.match(/-h[= ](\S+)/)
  if (hFlagMatch) {
    const val = hFlagMatch[1]
    if (!val.startsWith("-")) {
      const inner = val.match(/^https?:\/\/([^/\s:?#]+)/)
      add(inner ? inner[1] : val)
    }
  }

  // 4. Known tool positional arg
  const tokens = command.trim().split(/\s+/)
  const toolIdx = tokens.findIndex((t) => KNOWN_TOOLS.has(t.toLowerCase()))
  if (toolIdx !== -1) {
    // Walk tokens after tool name, skip flags and their values
    let i = toolIdx + 1
    while (i < tokens.length) {
      const tok = tokens[i]
      if (tok.startsWith("-")) {
        // Skip flags that consume a value (single letter flags with known value-consuming chars)
        // Heuristic: if next token doesn't start with -, it's a value; skip both
        if (i + 1 < tokens.length && !tokens[i + 1].startsWith("-")) {
          i += 2
        } else {
          i++
        }
        continue
      }
      // Non-flag token — this is our positional host candidate
      // Exclude if it looks like a file path
      if (!tok.startsWith("/") && !tok.includes("=")) {
        const inner = tok.match(/^https?:\/\/([^/\s:?#]+)/)
        add(inner ? inner[1] : tok)
        break
      }
      i++
    }
  }

  return hosts
}

// ---------------------------------------------------------------------------
// checkCommand
// ---------------------------------------------------------------------------

export function checkCommand(
  command: string,
  opts?: { allowlist?: string },
): BlocklistDecision {
  const rawAllowlist =
    opts?.allowlist ?? process.env["CTF_ALLOWLIST"] ?? ""
  const allowlist = rawAllowlist ? parseAllowlist(rawAllowlist) : []

  const hosts = extractHosts(command)

  if (hosts.length === 0) return { allowed: true }

  for (const host of hosts) {
    const result = isBlocked(host, allowlist)
    if (result.blocked) {
      return { allowed: false, reason: result.reason!, host }
    }
  }

  return { allowed: true }
}
