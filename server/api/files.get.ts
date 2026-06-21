import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join, isAbsolute, resolve } from 'node:path'
import { getClaudeDir } from '../utils/claudeDir'
import { isUnderAllowedPath, getAllowedPaths } from '../utils/path-security'

export default defineEventHandler(async (event) => {
  const query = getQuery(event)
  const path = query.path as string

  if (!path) {
    throw createError({ statusCode: 400, message: 'Path is required' })
  }

  const claudeDir = getClaudeDir()
  let fullPath: string

  if (!isAbsolute(path)) {
    // Relative paths resolve under the Claude dir only — no untrusted base
    fullPath = resolve(join(claudeDir, path))
  } else {
    fullPath = resolve(path)
  }

  // Security: restrict file access to allowed directories (claudeDir only)
  if (!isUnderAllowedPath(fullPath, getAllowedPaths())) {
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
