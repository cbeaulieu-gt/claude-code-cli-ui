import { resolve, join, normalize, relative, sep, isAbsolute } from 'node:path'
import { homedir } from 'node:os'
import { getClaudeDir } from './claudeDir'

/**
 * Returns true if resolvedFull is at or inside resolvedBase.
 * Uses path.relative() to avoid the Windows-separator bug from startsWith('/')
 * and to correctly reject shared-prefix siblings (e.g. /a/baseX vs /a/base).
 */
function isContained(resolvedBase: string, resolvedFull: string): boolean {
  const rel = relative(resolvedBase, resolvedFull)
  // '' means resolvedFull === resolvedBase (the base itself)
  // A safe child has a rel that is not absolute and doesn't start with '..'
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + sep))
}

/**
 * Resolve a path and verify it stays within the allowed base directory.
 * Prevents path traversal attacks (e.g., ../../etc/passwd).
 * Throws if the resolved path escapes the base.
 */
export function safePath(base: string, ...segments: string[]): string {
  const resolvedBase = resolve(base)
  const resolvedFull = resolve(resolvedBase, ...segments)

  if (!isContained(resolvedBase, resolvedFull)) {
    throw createError({
      statusCode: 403,
      message: 'Access denied: path outside allowed directory',
    })
  }

  return resolvedFull
}

/**
 * Resolve a path within the Claude config directory (~/.claude).
 * Throws if the result escapes the Claude dir.
 */
export function safeClaudePath(...segments: string[]): string {
  return safePath(getClaudeDir(), ...segments)
}

/**
 * Validate that a slug is safe for use in file paths.
 * Allows: lowercase letters, digits, single hyphens, and '--' for directory separators.
 * Rejects: '..', '/', '\', or any other path-sensitive characters.
 */
export function validateSlug(slug: string): void {
  if (!slug || typeof slug !== 'string') {
    throw createError({ statusCode: 400, message: 'Slug is required' })
  }

  // Reject path traversal patterns
  if (slug.includes('..') && !slug.includes('--')) {
    throw createError({ statusCode: 400, message: 'Invalid slug: contains path traversal' })
  }

  // Only allow safe characters: alphanumeric, hyphens, underscores
  // '--' is allowed as directory separator (decoded by agentUtils)
  if (!/^[a-zA-Z0-9][-a-zA-Z0-9_]*$/.test(slug)) {
    throw createError({ statusCode: 400, message: 'Invalid slug: contains unsafe characters' })
  }
}

/**
 * Check if a resolved path is under one of the allowed base directories.
 * Used for endpoints that accept absolute paths (e.g., files.get, directories.get).
 */
export function isUnderAllowedPath(targetPath: string, allowedBases: string[]): boolean {
  const resolved = resolve(targetPath)
  return allowedBases.some((base) => isContained(resolve(base), resolved))
}

/**
 * Get the list of allowed base directories for file access.
 * Returns only the Claude config directory — callers must NOT pass
 * untrusted (user-supplied) paths; server-validated project dirs
 * should be appended by the caller after validation.
 *
 * The optional argument is intentionally ignored: an attacker-controlled
 * directory arriving from an HTTP query must NOT widen the allowed set.
 */
export function getAllowedPaths(_ignored?: string): string[] {
  return [getClaudeDir()]
}

/**
 * Get the list of base directories allowed for browsing/reading project files.
 * Wider than getAllowedPaths: includes the user's home directory so the
 * FileEditorSidebar can read project files under ~/projects, etc.
 * Used by files.get and directories.get; reveal.post uses getAllowedPaths.
 */
export function getBrowsableRoots(): string[] {
  return [homedir(), getClaudeDir()]
}
