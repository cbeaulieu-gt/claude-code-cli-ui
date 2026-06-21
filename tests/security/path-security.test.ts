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
  getAllowedPaths,
  getBrowsableRoots,
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

// ---------------------------------------------------------------------------
// P1-REGRESSION: getAllowedPaths — attacker-supplied projectDir bypass
//
// BUG (files.get.ts): The endpoint read `projectDir` from the HTTP query and
// passed it into `getAllowedPaths(projectDir)`, which unconditionally pushed
// the caller-supplied directory as an allowed root.  An attacker could set
// `?projectDir=/etc` and `?path=/etc/passwd` to satisfy the isUnderAllowedPath
// guard and read arbitrary files.
//
// CONTRACT after fix: `getAllowedPaths()` called with no argument (or with a
// server-validated argument) must not permit access to paths outside ~/.claude
// or the legitimately-resolved project directory.  An attacker-controlled
// directory string arriving from the query MUST NOT widen the allowed roots.
//
// NOTE: An HTTP-level 403 assertion would be the ideal complement, but the
// existing E2E suite (api-security-e2e.test.ts) already has a C3 group that
// covers the files.get endpoint.  These unit tests pin the lower-level
// contract so a future refactor of getAllowedPaths cannot silently regress it
// without breaking tests that don't require a running server.
// ---------------------------------------------------------------------------

describe('P1-REGRESSION: getAllowedPaths — attacker-controlled projectDir bypass', () => {
  // An attacker-supplied directory used as a query param value.
  // We use os.tmpdir() so the path exists cross-platform (Windows/Linux).
  const ATTACKER_DIR = os.tmpdir()
  const ATTACKER_FILE = path.join(ATTACKER_DIR, 'secret.txt')

  it('positive control — a path under ~/.claude is allowed by default', () => {
    // With no projectDir argument only the Claude dir is an allowed root.
    const HOME = os.homedir()
    const claudeDir = path.join(HOME, '.claude')
    const claudeFile = path.join(claudeDir, 'agents', 'my-agent.md')
    const allowed = getAllowedPaths()

    // The allowed list must include at least the Claude dir.
    expect(allowed.length).toBeGreaterThanOrEqual(1)
    // A file under Claude dir must be permitted.
    expect(isUnderAllowedPath(claudeFile, allowed)).toBe(true)
  })

  it('a file outside ~/.claude is NOT allowed when no projectDir is supplied', () => {
    // Without a projectDir the allowed set contains only ~/.claude.
    // A file in os.tmpdir() is definitively outside that set.
    const allowed = getAllowedPaths()
    expect(isUnderAllowedPath(ATTACKER_FILE, allowed)).toBe(false)
  })

  it('REGRESSION — passing an attacker dir as projectDir must NOT grant access to files in that dir', () => {
    // BUG: getAllowedPaths(ATTACKER_DIR) currently returns [claudeDir, ATTACKER_DIR],
    // making isUnderAllowedPath(ATTACKER_FILE, ...) return true — the read guard is
    // bypassed.  After the fix, the endpoint will derive the project dir from a
    // server-validated source and never pass the raw query value here; this test
    // documents the intended contract: even if getAllowedPaths is called with an
    // arbitrary directory, a correct implementation must NOT allow it to widen
    // access to system paths.
    //
    // Currently FAILS because getAllowedPaths(ATTACKER_DIR) blindly pushes the
    // attacker dir into the allowed list.
    const allowed = getAllowedPaths(ATTACKER_DIR)
    // After fix: must be false — arbitrary dirs cannot be promoted to allowed roots.
    expect(isUnderAllowedPath(ATTACKER_FILE, allowed)).toBe(false)
  })

  it('REGRESSION — the allowed list must not grow when a non-claudeDir path is supplied', () => {
    // A related contract: passing a path that is NOT under ~/.claude and NOT a
    // validated project directory must not expand the allowed set.
    const allowed = getAllowedPaths(ATTACKER_DIR)
    // After fix: only claudeDir should be in the list; arbitrary dirs are rejected.
    // Currently FAILS because the buggy code pushes ATTACKER_DIR unconditionally.
    const HOME = os.homedir()
    const claudeDir = path.join(HOME, '.claude')
    const resolvedAllowed = allowed.map(p => path.resolve(p))
    expect(resolvedAllowed).not.toContain(path.resolve(ATTACKER_DIR))
    expect(resolvedAllowed.length).toBe(1)
    expect(resolvedAllowed[0]).toBe(path.resolve(claudeDir))
  })
})

// ---------------------------------------------------------------------------
// getBrowsableRoots — directory-browser boundary
//
// This function lifts the boundary used by the directory browser into
// path-security so files.get can authorise project-file reads against the
// same set: [os.homedir(), getClaudeDir()].
//
// INTENDED RED STATE: getBrowsableRoots is not exported from path-security.ts
// yet — the import above will fail with a SyntaxError / "is not a function"
// until the implementation agent adds the export.
// ---------------------------------------------------------------------------

describe('getBrowsableRoots', () => {
  it('returns an array that includes os.homedir()', () => {
    const roots = getBrowsableRoots()
    const resolvedRoots = roots.map(r => path.resolve(r))
    expect(resolvedRoots).toContain(path.resolve(os.homedir()))
  })

  it('returns an array that includes the Claude dir', () => {
    // getClaudeDir() defaults to os.homedir()/.claude when CLAUDE_DIR is unset.
    // We verify by checking that whatever it returns is a sub-path of — or equal
    // to — something in the list.  Using isUnderAllowedPath keeps us decoupled
    // from the exact value of getClaudeDir() in this environment.
    const roots = getBrowsableRoots()
    // The Claude dir itself must be either in roots OR a descendant of a root in
    // the list (homedir covers it when claudeDir is the default ~/.claude).
    // Either way, isUnderAllowedPath must be true for the Claude dir.
    const HOME = os.homedir()
    const defaultClaudeDir = path.join(HOME, '.claude')
    // If CLAUDE_DIR override is active, getBrowsableRoots should still include
    // it; if not, defaultClaudeDir is under homedir which is always in roots.
    expect(isUnderAllowedPath(defaultClaudeDir, roots)).toBe(true)
  })

  it('returns exactly two roots when the Claude dir is the default (~/.claude)', () => {
    // Without a CLAUDE_DIR override the two roots are homedir() and homedir()/.claude.
    // With an override the list still has two entries (homedir + overridden claudeDir).
    const roots = getBrowsableRoots()
    expect(roots.length).toBe(2)
  })

  it('allows a file nested under os.homedir() — regression for project-file reads', () => {
    // This is the regression test that proves legitimate project-file reads work.
    // The frontend FileEditorSidebar passes paths like /home/user/projects/app/src/index.ts
    // which must not 403 once getBrowsableRoots replaces the claudeDir-only list.
    const projectFile = path.join(os.homedir(), 'projects', 'app', 'src', 'index.ts')
    expect(isUnderAllowedPath(projectFile, getBrowsableRoots())).toBe(true)
  })

  it('blocks a system path that is outside os.homedir()', () => {
    // Choose a path guaranteed to be outside homedir on any OS.
    // On win32: C:\Windows\System32\drivers\etc\hosts is outside any user home.
    // On POSIX: /etc/passwd is outside any user home.
    const outsidePath =
      process.platform === 'win32'
        ? 'C:\\Windows\\System32\\drivers\\etc\\hosts'
        : '/etc/passwd'
    expect(isUnderAllowedPath(outsidePath, getBrowsableRoots())).toBe(false)
  })
})
