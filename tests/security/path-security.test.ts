/**
 * Tests for server/utils/path-security.ts
 *
 * All paths are built cross-platform using os.tmpdir() / os.homedir() and
 * path.join / path.resolve so the suite runs correctly on both Windows and
 * Linux without any hardcoded separator literals.
 *
 * `createError` is stubbed in tests/setup.ts (referenced from vitest.config.ts)
 * so the production module can be imported without a Nuxt runtime context.
 */
import { describe, it, expect } from 'vitest'
import * as path from 'node:path'
import * as os from 'node:os'
import {
  safePath,
  isUnderAllowedPath,
  validateSlug,
} from '../../server/utils/path-security'

// ---------------------------------------------------------------------------
// Cross-platform base paths derived from the OS at runtime
// ---------------------------------------------------------------------------

/** A stable temp-based directory that is guaranteed to exist on every OS. */
const TMP = os.tmpdir()

/** A base directory name used in containment tests. */
const BASE = path.join(TMP, 'test-base')

/** A sibling with a shared prefix — must NOT be treated as "inside" BASE. */
const BASE_EVIL = path.join(TMP, 'test-base-evil')

/** Home directory for isUnderAllowedPath fixture. */
const HOME = os.homedir()

const ALLOWED_BASES = [
  path.join(HOME, '.claude'),
  path.join(HOME, 'projects'),
]

// ---------------------------------------------------------------------------
// safePath
// ---------------------------------------------------------------------------

describe('safePath', () => {
  it('returns the resolved path when a single segment is inside the base', () => {
    const result = safePath(BASE, 'file.txt')
    expect(result).toBe(path.resolve(BASE, 'file.txt'))
  })

  it('returns the resolved path for nested segments inside the base', () => {
    const result = safePath(BASE, 'sub', 'dir', 'file.md')
    expect(result).toBe(path.resolve(BASE, 'sub', 'dir', 'file.md'))
  })

  it('allows the base directory itself (no segments)', () => {
    const result = safePath(BASE)
    expect(result).toBe(path.resolve(BASE))
  })

  it('allows a nested .. that resolves back inside the base', () => {
    // BASE/sub/../file.txt resolves to BASE/file.txt — still inside the base
    const result = safePath(BASE, 'sub', '..', 'file.txt')
    expect(result).toBe(path.resolve(BASE, 'file.txt'))
  })

  it('throws for a .. traversal that escapes the base', () => {
    // BASE/../etc/passwd resolves above BASE
    expect(() => safePath(BASE, '..', 'etc', 'passwd')).toThrow('Access denied')
  })

  it('throws for a double-.. traversal that escapes the base', () => {
    // BASE/sub/../../escape resolves two levels above BASE
    expect(() => safePath(BASE, 'sub', '..', '..', 'escape')).toThrow('Access denied')
  })

  it('throws when an absolute segment outside the base is supplied', () => {
    // path.resolve(BASE, absoluteOutsidePath) = absoluteOutsidePath on every OS
    const outside = path.join(TMP, 'etc', 'passwd')
    expect(() => safePath(BASE, outside)).toThrow('Access denied')
  })

  it('throws for a sibling directory with a shared prefix (prefix-confusion attack)', () => {
    // BASE_EVIL shares the prefix "test-base" with BASE but is not inside it
    expect(() => safePath(BASE, '..', 'test-base-evil', 'file')).toThrow('Access denied')
  })
})

// ---------------------------------------------------------------------------
// isUnderAllowedPath
// ---------------------------------------------------------------------------

describe('isUnderAllowedPath', () => {
  it('returns true for a path nested inside the first allowed base', () => {
    const target = path.join(HOME, '.claude', 'agents', 'test.md')
    expect(isUnderAllowedPath(target, ALLOWED_BASES)).toBe(true)
  })

  it('returns true for a path nested inside the second allowed base', () => {
    const target = path.join(HOME, 'projects', 'src', 'index.ts')
    expect(isUnderAllowedPath(target, ALLOWED_BASES)).toBe(true)
  })

  it('returns true for a path that exactly equals an allowed base', () => {
    const target = path.join(HOME, '.claude')
    expect(isUnderAllowedPath(target, ALLOWED_BASES)).toBe(true)
  })

  it('returns false for a path in a wholly unrelated directory', () => {
    // Use a TMP sub-path that is clearly not under HOME/.claude or HOME/projects
    const target = path.join(TMP, 'etc', 'passwd')
    expect(isUnderAllowedPath(target, ALLOWED_BASES)).toBe(false)
  })

  it('returns false for a hidden sibling of an allowed base (.ssh vs .claude)', () => {
    const target = path.join(HOME, '.ssh', 'id_rsa')
    expect(isUnderAllowedPath(target, ALLOWED_BASES)).toBe(false)
  })

  it('returns false for a path that shares a prefix but is not under an allowed base (prefix-confusion)', () => {
    // HOME/.claudeX is NOT under HOME/.claude — must not be treated as inside
    const target = path.join(HOME, '.claudeX', 'file')
    expect(isUnderAllowedPath(target, ALLOWED_BASES)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// validateSlug
// ---------------------------------------------------------------------------

describe('validateSlug', () => {
  it('accepts a simple alphanumeric slug', () => {
    expect(() => validateSlug('my-agent')).not.toThrow()
  })

  it('accepts slugs with underscores and hyphens', () => {
    expect(() => validateSlug('my_agent-v2')).not.toThrow()
  })

  it('throws for an empty slug', () => {
    expect(() => validateSlug('')).toThrow()
  })

  it('throws for a slug containing path-traversal characters', () => {
    expect(() => validateSlug('../etc/passwd')).toThrow()
  })

  it('throws for a slug containing a forward slash', () => {
    expect(() => validateSlug('a/b')).toThrow()
  })

  it('throws for a slug containing a backslash', () => {
    expect(() => validateSlug('a\\b')).toThrow()
  })
})
