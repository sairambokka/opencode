import { Effect, Schema } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./e2b.txt"
import { Sandbox as SandboxService } from "../sandbox/sandbox"
import { extractFlags } from "../sandbox/flag-detector"
import { checkCommand } from "../sandbox/blocklist"

// Flat schema (single Struct) instead of a discriminated union, so providers
// that strictly validate JSON Schema (DeepSeek, some OpenAI strict modes)
// accept it. The action discriminates which optional fields are used; the
// execute() body validates required fields per-action and returns a clear
// error if something is missing.
export const Parameters = Schema.Struct({
  action: Schema.Literals(["exec", "bg_exec", "bg_wait", "read", "write", "reset"])
    .annotate({
      description:
        "Operation to perform. Defaults to 'exec' if omitted. exec=run command, bg_exec=start background command, bg_wait=poll background pid, read=read file from sandbox, write=write file to sandbox, reset=destroy and recreate sandbox.",
      default: "exec",
    })
    .pipe(Schema.optional, Schema.withDecodingDefault(Effect.succeed("exec" as const))),
  command: Schema.optional(Schema.String).annotate({
    description: "Shell command. Required for action=exec or bg_exec.",
  }),
  description: Schema.optional(Schema.String).annotate({
    description: "One-line human description shown in the TUI. Required for action=exec or bg_exec.",
  }),
  cwd: Schema.optional(Schema.String).annotate({
    description: "Working directory inside the sandbox. Optional for exec/bg_exec.",
  }),
  timeout_ms: Schema.optional(Schema.Number).annotate({
    description: "Max ms to wait for exec (default 120000, clamped 1000-600000).",
  }),
  tail_only: Schema.optional(Schema.Boolean).annotate({
    description: "If true, return only the last ~200 lines of output (exec only).",
  }),
  pid: Schema.optional(Schema.Number).annotate({
    description: "Background process id returned by bg_exec. Required for action=bg_wait.",
  }),
  max_wait_ms: Schema.optional(Schema.Number).annotate({
    description: "Max ms to wait when polling a background pid (default 30000). For action=bg_wait.",
  }),
  path: Schema.optional(Schema.String).annotate({
    description: "Absolute path inside the sandbox. Required for action=read or write.",
  }),
  max_bytes: Schema.optional(Schema.Number).annotate({
    description: "Max bytes to read (default 200000). For action=read.",
  }),
  content: Schema.optional(Schema.String).annotate({
    description: "File content to write. Required for action=write.",
  }),
})

export type Params = Schema.Schema.Type<typeof Parameters>

interface E2BMetadata {
  action?: string
  description?: string
  output?: string
  blocked?: boolean
  exit?: number | null
  flags?: string[]
  pid?: number | null
  startedAt?: number | null
  stillRunning?: boolean
  path?: string
  truncated?: boolean
  outputPath?: string
}

const DEFAULT_TIMEOUT_MS = 120_000, MAX_TIMEOUT_MS = 600_000, MIN_TIMEOUT_MS = 1_000
const DEFAULT_MAX_BYTES = 200_000, DEFAULT_BG_WAIT_MS = 30_000, TAIL_LINES = 200

function clampTimeout(ms: number | undefined): number {
  const v = ms ?? DEFAULT_TIMEOUT_MS
  return Math.min(Math.max(v, MIN_TIMEOUT_MS), MAX_TIMEOUT_MS)
}

function formatExecOutput(
  exit: number | null,
  stdout: string,
  stderr: string,
  stillRunning?: boolean,
): string {
  const prefix = stillRunning ? "--- still running, partial output ---\n" : ""
  const out = stdout.trim() || "(empty)"
  const err = stderr.trim() || "(empty)"
  return `${prefix}exit: ${exit ?? "(none)"}\n--- stdout ---\n${out}\n--- stderr ---\n${err}`
}

function tailLines(text: string, n: number): string {
  const lines = text.split("\n")
  if (lines.length <= n) return text
  return lines.slice(-n).join("\n")
}

function flagSuffix(flags: string[]): string {
  if (flags.length === 0) return ""
  return "\n--- flags detected ---\n" + flags.join("\n")
}

export const E2BTool = Tool.define(
  "e2b",
  Effect.gen(function* () {
    const sandbox = yield* SandboxService.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Params, ctx: Tool.Context<E2BMetadata>): Effect.Effect<Tool.ExecuteResult<E2BMetadata>> =>
        Effect.gen(function* () {
          const missing = (field: string, action: string) => ({
            title: `e2b ${action} (invalid)`,
            output: `Missing required field "${field}" for action="${action}".`,
            metadata: { action, blocked: true, exit: null, flags: [] } satisfies E2BMetadata,
          })

          // ---- exec ----
          if (params.action === "exec") {
            if (!params.command) return missing("command", "exec")
            if (!params.description) return missing("description", "exec")

            const decision = checkCommand(params.command)
            if (!decision.allowed) {
              return {
                title: params.description,
                output: `BLOCKED by safety blocklist (host=${decision.host}, reason=${decision.reason}). To allow, add to CTF_ALLOWLIST env var.`,
                metadata: {
                  action: "exec",
                  description: params.description,
                  blocked: true,
                  exit: null,
                  flags: [],
                },
              }
            }

            yield* ctx.metadata({ metadata: { output: "", description: params.description } })

            const timeoutMs = clampTimeout(params.timeout_ms)
            const result = yield* sandbox.exec(ctx.sessionID, {
              command: params.command,
              cwd: params.cwd,
              timeoutMs,
            })

            let combined = formatExecOutput(result.exit, result.stdout, result.stderr)
            if (params.tail_only) {
              combined = tailLines(combined, TAIL_LINES)
            }

            const flags = extractFlags(result.stdout + "\n" + result.stderr)
            combined += flagSuffix(flags)

            yield* ctx.metadata({
              metadata: { output: combined, description: params.description },
            })

            return {
              title: params.description,
              output: combined,
              metadata: {
                action: "exec",
                description: params.description,
                exit: result.exit,
                flags,
              },
            }
          }

          // ---- bg_exec ----
          if (params.action === "bg_exec") {
            if (!params.command) return missing("command", "bg_exec")
            if (!params.description) return missing("description", "bg_exec")

            const decision = checkCommand(params.command)
            if (!decision.allowed) {
              return {
                title: `bg: ${params.description}`,
                output: `BLOCKED by safety blocklist (host=${decision.host}, reason=${decision.reason}). To allow, add to CTF_ALLOWLIST env var.`,
                metadata: {
                  action: "bg_exec",
                  description: params.description,
                  blocked: true,
                  pid: null,
                  startedAt: null,
                },
              }
            }

            const handle = yield* sandbox.bgExec(ctx.sessionID, {
              command: params.command,
              cwd: params.cwd,
            })

            return {
              title: `bg: ${params.description}`,
              output: `started background process pid=${handle.pid}\ncommand: ${handle.command}\nuse e2b action: "bg_wait" with pid=${handle.pid} to fetch progress.`,
              metadata: {
                action: "bg_exec",
                description: params.description,
                pid: handle.pid,
                startedAt: handle.startedAt,
              },
            }
          }

          // ---- bg_wait ----
          if (params.action === "bg_wait") {
            if (params.pid === undefined) return missing("pid", "bg_wait")
            const maxWaitMs = params.max_wait_ms ?? DEFAULT_BG_WAIT_MS
            const result = yield* sandbox.bgWait(ctx.sessionID, params.pid, maxWaitMs)

            let combined = formatExecOutput(result.exit, result.stdout, result.stderr, result.stillRunning)
            const flags = extractFlags(result.stdout + "\n" + result.stderr)
            combined += flagSuffix(flags)

            return {
              title: `bg_wait pid=${params.pid}`,
              output: combined,
              metadata: {
                action: "bg_wait",
                pid: params.pid,
                stillRunning: result.stillRunning,
                exit: result.exit,
                flags,
              },
            }
          }

          // ---- read ----
          if (params.action === "read") {
            if (!params.path) return missing("path", "read")
            const maxBytes = params.max_bytes ?? DEFAULT_MAX_BYTES
            const content = yield* sandbox.read(ctx.sessionID, params.path, maxBytes)
            const flags = extractFlags(content)
            const output = content + flagSuffix(flags)

            return {
              title: `read ${params.path}`,
              output,
              metadata: {
                action: "read",
                path: params.path,
                flags,
              },
            }
          }

          // ---- write ----
          if (params.action === "write") {
            if (!params.path) return missing("path", "write")
            if (params.content === undefined) return missing("content", "write")
            yield* sandbox.write(ctx.sessionID, params.path, params.content)

            return {
              title: `write ${params.path}`,
              output: `wrote ${params.content.length} bytes to ${params.path}`,
              metadata: {
                action: "write",
                path: params.path,
              },
            }
          }

          // ---- reset ----
          yield* sandbox.reset(ctx.sessionID)

          return {
            title: "sandbox reset",
            output: "sandbox reset. fresh Kali instance will be created on next exec.",
            metadata: {
              action: "reset",
            },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
