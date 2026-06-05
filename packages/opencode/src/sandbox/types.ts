export type ExecResult = {
  exit: number | null
  stdout: string
  stderr: string
  truncated: boolean
  outputPath?: string
}

export type BackgroundHandle = {
  pid: number
  command: string
  startedAt: number
}
