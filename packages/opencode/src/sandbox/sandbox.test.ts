/**
 * Integration tests for Sandbox.Service.
 *
 * These tests require a real E2B sandbox environment and are skipped unless
 * E2B_API_KEY is set in the environment.
 *
 * Run with: E2B_API_KEY=xxx bun test packages/opencode/src/sandbox/sandbox.test.ts
 */

import { describe, expect, test } from "bun:test"
import { Effect, Layer } from "effect"
import { Service, layer as SandboxLayer } from "./sandbox"

const SKIP = !process.env["E2B_API_KEY"]
const it = SKIP ? test.skip : test

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Run an Effect using the Sandbox layer in isolation.
 *
 * InstanceState.make relies on InstanceRef being provided. Because
 * sandbox.ts does NOT use InstanceState (it uses a plain Map scoped to the
 * layer), we can run the layer directly without an instance context.
 */
function run<A>(effect: Effect.Effect<A, unknown, Service>): Promise<A> {
  return Effect.runPromise(Effect.provide(effect, SandboxLayer)) as Promise<A>
}

const SESSION = "test-session-1"

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Sandbox.Service", () => {
  it("acquire → exec echo hello → exit 0, stdout contains hello; second acquire is same sandbox", async () => {
    await run(
      Effect.gen(function* () {
        const svc = yield* Service
        const sb1 = yield* svc.acquire(SESSION)
        const result = yield* svc.exec(SESSION, {
          command: "echo hello",
          timeoutMs: 15_000,
        })
        expect(result.exit).toBe(0)
        expect(result.stdout.trim()).toBe("hello")

        // Second acquire must return the same Sandbox instance (no recreation)
        const sb2 = yield* svc.acquire(SESSION)
        expect(sb1).toBe(sb2)
      }),
    )
  })

  it("reset → subsequent acquire creates a different Sandbox instance", async () => {
    await run(
      Effect.gen(function* () {
        const svc = yield* Service
        const sb1 = yield* svc.acquire(SESSION)
        yield* svc.reset(SESSION)
        const sb2 = yield* svc.acquire(SESSION)
        expect(sb1).not.toBe(sb2)
      }),
    )
  })

  it("kill removes entry; subsequent acquire creates a fresh sandbox", async () => {
    const SESSION2 = "test-session-kill"
    await run(
      Effect.gen(function* () {
        const svc = yield* Service
        const sb1 = yield* svc.acquire(SESSION2)
        yield* svc.kill(SESSION2)
        // After kill the entry is gone — next acquire creates a new one
        const sb2 = yield* svc.acquire(SESSION2)
        expect(sb1).not.toBe(sb2)
        // Clean up
        yield* svc.kill(SESSION2)
      }),
    )
  })

  it("read /etc/hostname returns a non-empty string", async () => {
    await run(
      Effect.gen(function* () {
        const svc = yield* Service
        yield* svc.acquire(SESSION)
        const content = yield* svc.read(SESSION, "/etc/hostname", 4096)
        expect(content.length).toBeGreaterThan(0)
      }),
    )
  })
})
