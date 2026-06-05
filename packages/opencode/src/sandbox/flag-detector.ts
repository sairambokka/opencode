const FLAG_REGEX = /(?:flag|FLAG|CTF|HTB|picoCTF|THM)\{[^}\s]{3,200}\}/g

export function extractFlags(text: string): string[] {
  if (typeof text !== "string" || text.length === 0) return []

  const seen = new Set<string>()
  const results: string[] = []

  for (const match of text.matchAll(FLAG_REGEX)) {
    const flag = match[0]
    if (!seen.has(flag)) {
      seen.add(flag)
      results.push(flag)
    }
  }

  return results
}
