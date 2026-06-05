import { describe, expect, test } from "bun:test"
import { extractFlags } from "./flag-detector"

describe("extractFlags", () => {
  test("extracts a single flag{...} match", () => {
    expect(extractFlags("You found flag{abc123}!")).toEqual(["flag{abc123}"])
  })

  test("extracts multiple flags in encounter order", () => {
    const text = "First: flag{one_flag_here} then CTF{second_one_x}"
    expect(extractFlags(text)).toEqual(["flag{one_flag_here}", "CTF{second_one_x}"])
  })

  test("collapses duplicate flags", () => {
    const text = "flag{dup_value_here} and again flag{dup_value_here}"
    expect(extractFlags(text)).toEqual(["flag{dup_value_here}"])
  })

  test("handles mixed-case prefixes", () => {
    const text = "HTB{some_htb_flag} picoCTF{some_pico_flag}"
    expect(extractFlags(text)).toEqual(["HTB{some_htb_flag}", "picoCTF{some_pico_flag}"])
  })

  test("rejects whitespace inside braces", () => {
    expect(extractFlags("flag{ab cd}")).toEqual([])
  })

  test("rejects content shorter than 3 chars inside braces", () => {
    expect(extractFlags("flag{ab}")).toEqual([])
  })

  test("returns [] for empty string", () => {
    expect(extractFlags("")).toEqual([])
  })

  test("returns [] for non-string input", () => {
    // Cast to defeat TypeScript so we can test the runtime guard
    expect(extractFlags(null as unknown as string)).toEqual([])
    expect(extractFlags(undefined as unknown as string)).toEqual([])
    expect(extractFlags(42 as unknown as string)).toEqual([])
  })

  test("finds flags in realistic multi-line blob with ANSI escapes", () => {
    const blob = [
      "\x1b[32m[*]\x1b[0m Solving challenge...",
      "Output: \x1b[33msome noise here\x1b[0m",
      "Result: picoCTF{r3al_flag_value_123}",
      "\x1b[31m[!]\x1b[0m Done.",
      "Also found HTB{another_flag_456} in memory",
    ].join("\n")

    expect(extractFlags(blob)).toEqual(["picoCTF{r3al_flag_value_123}", "HTB{another_flag_456}"])
  })
})
