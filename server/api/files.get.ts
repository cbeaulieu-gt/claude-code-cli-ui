import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join, isAbsolute, resolve, relative, sep } from 'node:path'
import { homedir } from 'node:os'
import { getClaudeDir } from '../utils/claudeDir'
import { isUnderAllowedPath, getBrowsableRoots } from '../utils/path-security'

/**
 * Returns true if fullPath is inside a hidden directory directly under home
 * (e.g. ~/.ssh, ~/.gnupg) AND is NOT inside the Claude config dir.
 * Those directories are off-limits even though homedir() is a browsable root.
 */
function isSensitiveHomeSubdir(fullPath: string, home: string, claudeDir: string): boolean {
  // Anything under claudeDir is explicitly allowed — not sensitive
  const relToClaudeDir = relative(resolve(claudeDir), resolve(fullPath))
  if (!relToClaudeDir.startsWith('..')) return false

  // Check if the first path segment below home is a hidden dir (starts with '.')
  const relToHome = relative(resolve(home), resolve(fullPath))
  if (relToHome.startsWith('..')) return false // not under home at all
  const firstSegment = relToHome.split(sep)[0]
  return firstSegment.startsWith('.')
}

export default defineEventHandler(async (event) => {
  const query = getQuery(event)
  const path = query.path as string

  if (!path) {
    throw createError({ statusCode: 400, message: 'Path is required' })
  }

  const claudeDir = getClaudeDir()
  const home = homedir()
  let fullPath: string

  if (!isAbsolute(path)) {
    // Relative paths resolve under the Claude dir only — no untrusted base
    fullPath = resolve(join(claudeDir, path))
  } else {
    fullPath = resolve(path)
  }

  // Security: allow files under the user's home dir or Claude dir (restores
  // project-file reads from FileEditorSidebar); paths outside home still 403.
  // Hidden subdirectories directly under home (e.g. ~/.ssh) are also blocked
  // except for the Claude dir itself.
  // 403 takes precedence over 404 to avoid leaking path existence.
  if (!isUnderAllowedPath(fullPath, getBrowsableRoots()) || isSensitiveHomeSubdir(fullPath, home, claudeDir)) {
    throw createError({ statusCode: 403, message: 'Access denied: path outside allowed directory' })
  }

  if (!existsSync(fullPath)) {
    throw createError({ statusCode: 404, message: 'File not found' })
  }

  try {
    const content = await readFile(fullPath, 'utf-8')
    return { content, path: fullPath }
  } catch (err: any) {
    throw createError({ statusCode: 500, message: 'Failed to read file' })
  }
})
