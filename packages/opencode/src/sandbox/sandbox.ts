import { Context, Effect, Layer } from "effect"
import * as Log from "@opencode-ai/core/util/log"
import { Sandbox } from "e2b"
import type { BackgroundHandle } from "./types"

// ---------- Logging ----------

const log = Log.create({ service: "sandbox" })

// ---------- Constants ----------

const TEMPLATE_ID = process.env["E2B_TEMPLATE_ID"] ?? "md57fwzxinsmuzinmbky"
const IDLE_TIMEOUT_MS = 30 * 60 * 1000 // 30 minutes
const IDLE_CHECK_INTERVAL_MS = 5 * 60 * 1000 // 5 minutes

// ---------- State types ----------

// E2B background handle type is not publicly exported; typed loosely here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyHandle = any

type BgEntry = {
  handle: AnyHandle
  stdoutBuf: string
  stderrBuf: string
  exit: number | null
}

type SandboxEntry = {
  sb: Sandbox
  background: Map<number, BgEntry>
  createdAt: number
  lastActive: number
}

// ---------- E2B result shape (SDK returns these fields) ----------

type CommandResult = {
  exitCode: number | null | undefined
  stdout: string | undefined
  stderr: string | undefined
}

// ---------- Interface ----------

export interface Interface {
  readonly acquire: (sessionID: string) => Effect.Effect<Sandbox>
  readonly exec: (
    sessionID: string,
    opts: {
      command: string
      cwd?: string
      timeoutMs: number
      onStdout?: (chunk: string) => void
      onStderr?: (chunk: string) => void
    },
  ) => Effect.Effect<{ exit: number | null; stdout: string; stderr: string }>
  readonly bgExec: (
    sessionID: string,
    opts: { command: string; cwd?: string },
  ) => Effect.Effect<BackgroundHandle>
  readonly bgWait: (
    sessionID: string,
    pid: number,
    maxWaitMs: number,
  ) => Effect.Effect<{ exit: number | null; stdout: string; stderr: string; stillRunning: boolean }>
  readonly read: (sessionID: string, path: string, maxBytes: number) => Effect.Effect<string>
  readonly write: (sessionID: string, path: string, content: string) => Effect.Effect<void>
  readonly reset: (sessionID: string) => Effect.Effect<void>
  readonly kill: (sessionID: string) => Effect.Effect<void>
}

// ---------- Service ----------

export class Service extends Context.Service<Service, Interface>()("@opencode/Sandbox") {}

// ---------- Helpers ----------

function sandboxOpts(): { apiKey?: string } {
  const apiKey = process.env["E2B_API_KEY"]
  return apiKey ? { apiKey } : {}
}

// Monotonic counter for background handles whose PID the SDK does not provide.
let bgPidCounter = 100_000

function createEntry(sb: Sandbox): SandboxEntry {
  const now = Date.now()
  return { sb, background: new Map(), createdAt: now, lastActive: now }
}

// ---------- Layer ----------

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    // Per-session sandbox map — lives for the lifetime of this layer scope.
    const sandboxes = new Map<string, SandboxEntry>()

    // -- acquire ----------------------------------------------------------
    const acquire = (sessionID: string): Effect.Effect<Sandbox> =>
      Effect.gen(function* () {
        const existing = sandboxes.get(sessionID)
        if (existing) {
          existing.lastActive = Date.now()
          return existing.sb
        }
        log.info("creating sandbox", { sessionID, template: TEMPLATE_ID })
        const sb = yield* Effect.tryPromise({
          try: () => Sandbox.create(TEMPLATE_ID, sandboxOpts()),
          catch: (err) => new Error(`Failed to create sandbox for session ${sessionID}: ${String(err)}`),
        })
        sandboxes.set(sessionID, createEntry(sb))
        return sb
      }).pipe(Effect.orDie)

    // -- exec -------------------------------------------------------------
    const exec = (
      sessionID: string,
      opts: {
        command: string
        cwd?: string
        timeoutMs: number
        onStdout?: (chunk: string) => void
        onStderr?: (chunk: string) => void
      },
    ): Effect.Effect<{ exit: number | null; stdout: string; stderr: string }> =>
      Effect.gen(function* () {
        const sb = yield* acquire(sessionID)
        const raw = yield* Effect.tryPromise({
          try: () =>
            sb.commands.run(opts.command, {
              timeoutMs: opts.timeoutMs,
              cwd: opts.cwd,
              onStdout: opts.onStdout,
              onStderr: opts.onStderr,
            }) as Promise<CommandResult>,
          catch: (err) => {
            const msg = String(err)
            // Mark sandbox as dead so the next acquire recreates it
            if (msg.includes("sandbox not found") || (msg.includes("sandbox") && msg.includes("dead"))) {
              sandboxes.delete(sessionID)
            }
            return new Error(`exec failed for session ${sessionID}: ${msg}`)
          },
        })
        const entry = sandboxes.get(sessionID)
        if (entry) entry.lastActive = Date.now()
        return {
          exit: raw.exitCode ?? null,
          stdout: raw.stdout ?? "",
          stderr: raw.stderr ?? "",
        }
      }).pipe(Effect.orDie)

    // -- bgExec -----------------------------------------------------------
    const bgExec = (
      sessionID: string,
      opts: { command: string; cwd?: string },
    ): Effect.Effect<BackgroundHandle> =>
      Effect.gen(function* () {
        const sb = yield* acquire(sessionID)
        const entry = sandboxes.get(sessionID)!
        let stdoutBuf = ""
        let stderrBuf = ""
        const handle: AnyHandle = yield* Effect.tryPromise({
          try: () =>
            sb.commands.run(opts.command, {
              background: true,
              cwd: opts.cwd,
              onStdout: (chunk: string) => { stdoutBuf += chunk },
              onStderr: (chunk: string) => { stderrBuf += chunk },
            }),
          catch: (err) => new Error(`bgExec failed for session ${sessionID}: ${String(err)}`),
        })

        // E2B's background handle may expose a pid; fall back to a local
        // monotonic counter if the SDK does not provide one (typed `any`).
        const pid: number = typeof handle?.pid === "number" ? (handle.pid as number) : bgPidCounter++

        entry.background.set(pid, { handle, stdoutBuf, stderrBuf, exit: null })
        entry.lastActive = Date.now()
        log.info("bgExec started", { sessionID, pid, command: opts.command })
        return { pid, command: opts.command, startedAt: Date.now() }
      }).pipe(Effect.orDie)

    // -- bgWait -----------------------------------------------------------
    const bgWait = (
      sessionID: string,
      pid: number,
      maxWaitMs: number,
    ): Effect.Effect<{ exit: number | null; stdout: string; stderr: string; stillRunning: boolean }> =>
      Effect.gen(function* () {
        const entry = sandboxes.get(sessionID)
        if (!entry) {
          return { exit: null, stdout: "", stderr: "", stillRunning: false }
        }
        const bg = entry.background.get(pid)
        if (!bg) {
          return { exit: null, stdout: "", stderr: "", stillRunning: false }
        }

        const finished: boolean = yield* Effect.promise(async () => {
          try {
            if (typeof bg.handle?.wait === "function") {
              const result = await Promise.race([
                (bg.handle.wait({ timeoutMs: maxWaitMs }) as Promise<void>).then(() => true),
                new Promise<false>((resolve) => setTimeout(() => resolve(false), maxWaitMs)),
              ])
              return result
            }
            // Fallback: poll the exitCode property for maxWaitMs
            const deadline = Date.now() + maxWaitMs
            while (Date.now() < deadline) {
              if (bg.handle?.exitCode !== undefined && bg.handle?.exitCode !== null) return true
              await new Promise<void>((r) => setTimeout(r, 200))
            }
            return false
          } catch {
            return false
          }
        })

        if (finished) {
          const exitCode: number | null =
            typeof bg.handle?.exitCode === "number"
              ? (bg.handle.exitCode as number)
              : typeof bg.handle?.result?.exitCode === "number"
                ? (bg.handle.result.exitCode as number)
                : null
          bg.exit = exitCode
        }

        entry.lastActive = Date.now()
        return {
          exit: bg.exit,
          stdout: bg.stdoutBuf,
          stderr: bg.stderrBuf,
          stillRunning: !finished,
        }
      })

    // -- read -------------------------------------------------------------
    const read = (sessionID: string, path: string, maxBytes: number): Effect.Effect<string> =>
      Effect.gen(function* () {
        const sb = yield* acquire(sessionID)
        const content: string = yield* Effect.tryPromise({
          try: () => sb.files.read(path) as Promise<string>,
          catch: (err) => new Error(`read failed for session ${sessionID} path ${path}: ${String(err)}`),
        })
        const entry = sandboxes.get(sessionID)
        if (entry) entry.lastActive = Date.now()
        if (Buffer.byteLength(content, "utf-8") <= maxBytes) return content
        // Tail the content to last maxBytes, preserving UTF-8 boundary
        const buf = Buffer.from(content, "utf-8")
        const sliced = buf.subarray(buf.length - maxBytes).toString("utf-8")
        return `[truncated: file is ${buf.length} bytes, showing last ${maxBytes}]\n` + sliced
      }).pipe(Effect.orDie)

    // -- write ------------------------------------------------------------
    const write = (sessionID: string, path: string, content: string): Effect.Effect<void> =>
      Effect.gen(function* () {
        const sb = yield* acquire(sessionID)
        yield* Effect.tryPromise({
          try: async () => {
            await sb.files.write(path, content)
          },
          catch: (err) => new Error(`write failed for session ${sessionID} path ${path}: ${String(err)}`),
        })
        const entry = sandboxes.get(sessionID)
        if (entry) entry.lastActive = Date.now()
      }).pipe(Effect.orDie)

    // -- reset ------------------------------------------------------------
    const reset = (sessionID: string): Effect.Effect<void> =>
      Effect.gen(function* () {
        const entry = sandboxes.get(sessionID)
        if (entry) {
          yield* Effect.promise(() => entry.sb.kill().catch(() => undefined))
          sandboxes.delete(sessionID)
          log.info("sandbox reset", { sessionID })
        }
      })

    // -- kill -------------------------------------------------------------
    const kill = (sessionID: string): Effect.Effect<void> =>
      Effect.gen(function* () {
        const entry = sandboxes.get(sessionID)
        if (entry) {
          yield* Effect.promise(() => entry.sb.kill().catch(() => undefined))
          sandboxes.delete(sessionID)
          log.info("sandbox killed", { sessionID })
        }
      })

    // -- Idle reaper: runs every 5 minutes, kills sandboxes idle >30 min --
    yield* Effect.forkScoped(
      Effect.forever(
        Effect.gen(function* () {
          yield* Effect.sleep(`${IDLE_CHECK_INTERVAL_MS} millis`)
          const now = Date.now()
          for (const [sid, entry] of sandboxes) {
            if (now - entry.lastActive > IDLE_TIMEOUT_MS) {
              log.info("killing idle sandbox", { sessionID: sid })
              yield* Effect.promise(() => entry.sb.kill().catch(() => undefined))
              sandboxes.delete(sid)
            }
          }
        }),
      ),
    )

    // -- Scope finalizer: kill all sandboxes on layer teardown ------------
    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        log.info("shutting down all sandboxes", { count: sandboxes.size })
        await Promise.allSettled([...sandboxes.values()].map((e) => e.sb.kill()))
        sandboxes.clear()
      }),
    )

    // TODO: subscribe to session.deleted Bus events to eagerly kill sandboxes
    // when a session is closed by the user.

    return Service.of({ acquire, exec, bgExec, bgWait, read, write, reset, kill })
  }),
)

export const defaultLayer = layer

export * as Sandbox from "./sandbox"
