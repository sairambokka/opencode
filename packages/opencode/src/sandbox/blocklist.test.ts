import { describe, expect, test } from "bun:test"
import {
  checkCommand,
  extractHosts,
  ipInCidr,
  isBlocked,
} from "./blocklist"

describe("ipInCidr", () => {
  test("10.20.30.40 is in 10.0.0.0/8", () => {
    expect(ipInCidr("10.20.30.40", "10.0.0.0/8")).toBe(true)
  })

  test("11.0.0.1 is NOT in 10.0.0.0/8", () => {
    expect(ipInCidr("11.0.0.1", "10.0.0.0/8")).toBe(false)
  })

  test("192.168.1.1 is in 192.168.0.0/16", () => {
    expect(ipInCidr("192.168.1.1", "192.168.0.0/16")).toBe(true)
  })

  test("172.20.0.1 is in 172.16.0.0/12", () => {
    expect(ipInCidr("172.20.0.1", "172.16.0.0/12")).toBe(true)
  })
})

describe("extractHosts", () => {
  test("curl https://example.com extracts example.com", () => {
    expect(extractHosts("curl https://example.com")).toContain("example.com")
  })

  test("curl https://10.0.0.1/foo extracts 10.0.0.1", () => {
    expect(extractHosts("curl https://10.0.0.1/foo")).toContain("10.0.0.1")
  })

  test("nmap example.gov extracts example.gov", () => {
    expect(extractHosts("nmap example.gov")).toContain("example.gov")
  })

  test("cat /etc/hosts extracts nothing", () => {
    expect(extractHosts("cat /etc/hosts")).toHaveLength(0)
  })

  test("gobuster with -u flag extracts host", () => {
    const hosts = extractHosts(
      "gobuster -u http://target.example/admin -w /usr/share/wordlists/x.txt",
    )
    expect(hosts).toContain("target.example")
  })
})

describe("isBlocked", () => {
  test("example.com is not blocked", () => {
    expect(isBlocked("example.com", [])).toEqual({ blocked: false })
  })

  test("10.0.0.1 is blocked (RFC1918)", () => {
    const result = isBlocked("10.0.0.1", [])
    expect(result.blocked).toBe(true)
    expect(result.reason).toMatch(/RFC1918/i)
  })

  test("10.0.0.1 is allowed when CIDR is in allowlist", () => {
    expect(isBlocked("10.0.0.1", ["10.0.0.0/8"])).toEqual({ blocked: false })
  })

  test("localhost is blocked", () => {
    const result = isBlocked("localhost", [])
    expect(result.blocked).toBe(true)
    expect(result.reason).toMatch(/loopback/i)
  })

  test("::1 is blocked", () => {
    const result = isBlocked("::1", [])
    expect(result.blocked).toBe(true)
  })

  test("example.gov is blocked", () => {
    const result = isBlocked("example.gov", [])
    expect(result.blocked).toBe(true)
    expect(result.reason).toMatch(/\.gov/i)
  })

  test("example.mil is blocked", () => {
    const result = isBlocked("example.mil", [])
    expect(result.blocked).toBe(true)
    expect(result.reason).toMatch(/\.mil/i)
  })

  test("shop.htb.lab is allowed with wildcard *.htb.lab", () => {
    expect(isBlocked("shop.htb.lab", ["*.htb.lab"])).toEqual({ blocked: false })
  })
})

describe("checkCommand", () => {
  test("curl https://example.com → allowed", () => {
    expect(checkCommand("curl https://example.com")).toEqual({ allowed: true })
  })

  test("curl https://10.0.0.1/foo → blocked, RFC1918", () => {
    const result = checkCommand("curl https://10.0.0.1/foo")
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.reason).toMatch(/RFC1918/i)
      expect(result.host).toBe("10.0.0.1")
    }
  })

  test("nmap example.gov → blocked, .gov TLD", () => {
    const result = checkCommand("nmap example.gov")
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.reason).toMatch(/\.gov/i)
    }
  })

  test("nmap 127.0.0.1 → blocked, loopback", () => {
    const result = checkCommand("nmap 127.0.0.1")
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.reason).toMatch(/loopback/i)
    }
  })

  test("nmap 10.10.10.42 with allowlist 10.10.10.0/24 → allowed", () => {
    const result = checkCommand("nmap 10.10.10.42", {
      allowlist: "10.10.10.0/24",
    })
    expect(result.allowed).toBe(true)
  })

  test("nmap 10.10.10.42 without allowlist → blocked", () => {
    const result = checkCommand("nmap 10.10.10.42")
    expect(result.allowed).toBe(false)
  })

  test("curl https://shop.htb.lab with allowlist *.htb.lab → allowed", () => {
    const result = checkCommand("curl https://shop.htb.lab", {
      allowlist: "*.htb.lab",
    })
    expect(result.allowed).toBe(true)
  })

  test("cat /etc/hosts → allowed (no host extracted)", () => {
    expect(checkCommand("cat /etc/hosts")).toEqual({ allowed: true })
  })

  test("gobuster with non-blocked host → allowed", () => {
    const result = checkCommand(
      "gobuster -u http://target.example/admin -w /usr/share/wordlists/x.txt",
    )
    expect(result.allowed).toBe(true)
  })
})
