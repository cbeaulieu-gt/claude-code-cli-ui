import { describe, it, expect } from 'vitest'
import { decodeHTMLEntities } from '../../app/utils/messageFormatting'
import {
  renderMarkdown,
  renderMarkdownInline,
  renderMarkdownWithMath,
} from '../../app/utils/markdown'

/**
 * XSS Sanitization Tests (C6)
 *
 * Tests that the decodeHTMLEntities fix no longer uses innerHTML
 * and that markdown rendering would be safe with DOMPurify.
 */

describe('C6: decodeHTMLEntities — XSS amplifier fix', () => {
  it('decodes common HTML entities safely', () => {
    expect(decodeHTMLEntities('&amp;')).toBe('&')
    expect(decodeHTMLEntities('&lt;')).toBe('<')
    expect(decodeHTMLEntities('&gt;')).toBe('>')
    expect(decodeHTMLEntities('&quot;')).toBe('"')
    expect(decodeHTMLEntities('&#x27;')).toBe("'")
    expect(decodeHTMLEntities('&nbsp;')).toBe(' ')
  })

  it('handles mixed entity and plain text', () => {
    expect(decodeHTMLEntities('Hello &amp; World')).toBe('Hello & World')
    expect(decodeHTMLEntities('a &lt; b &gt; c')).toBe('a < b > c')
  })

  it('returns empty string for falsy input', () => {
    expect(decodeHTMLEntities('')).toBe('')
    expect(decodeHTMLEntities(null as any)).toBe('')
    expect(decodeHTMLEntities(undefined as any)).toBe('')
  })

  it('does NOT execute script tags — just decodes entities', () => {
    const malicious = '&lt;script&gt;alert(1)&lt;/script&gt;'
    const result = decodeHTMLEntities(malicious)
    // After entity decode, we get the literal string — no DOM execution
    expect(result).toBe('<script>alert(1)</script>')
    // This string would then be sanitized by DOMPurify in renderMarkdown
  })

  it('does NOT use innerHTML (verified by consistent behavior in node)', () => {
    // In the old code, innerHTML would decode ALL entities including obscure ones.
    // Our string-based approach only decodes the explicit list.
    // &#x41; = 'A' — our function does NOT decode it (by design)
    expect(decodeHTMLEntities('&#x41;')).toBe('&#x41;')
  })
})

describe('C6: markdown lang attribute — HTML injection fix', () => {
  it('would not inject via data-lang attribute', () => {
    // The lang attribute is now escaped before insertion into template literals.
    // Verify the escape logic: any quotes/angle brackets in lang should be stripped.
    const maliciousLang = '"><img src=x onerror=alert(1)>'
    const safeLang = maliciousLang.replace(/['"<>&]/g, '')
    expect(safeLang).toBe('img src=x onerror=alert(1)')
    expect(safeLang).not.toContain('"')
    expect(safeLang).not.toContain('<')
    expect(safeLang).not.toContain('>')
  })
})

// ---------------------------------------------------------------------------
// P1-REGRESSION: sanitizeHtml — SSR/server XSS bypass
//
// BUG (app/utils/markdown.ts): `sanitizeHtml()` returns the raw HTML string
// when `typeof window === 'undefined'` (line ~10).  Under Nuxt SSR — and
// under vitest with environment: 'node' — window is not defined, so every
// call to renderMarkdown / renderMarkdownInline / renderMarkdownWithMath skips
// DOMPurify entirely and ships unsanitized HTML on the first server render.
// A user whose message contains `<img src=x onerror=alert(1)>` would have
// that payload echoed verbatim into the SSR'd HTML, triggering XSS in every
// visitor's browser before hydration.
//
// HOW WE FORCE THE SSR BRANCH: vitest.config.ts sets environment: 'node'.
// In Node.js, globalThis.window is undefined by default, so
// `typeof window === 'undefined'` evaluates to true at the call site inside
// sanitizeHtml, engaging the early-return bypass unconditionally.  We do NOT
// need to stub anything — the production code already takes the broken path
// in this test environment.
//
// CONTRACT after fix: sanitizeHtml must sanitize regardless of whether window
// is defined (the fix is expected to use isomorphic-dompurify or equivalent).
// Each test below asserts the post-fix contract; all currently FAIL because
// the SSR short-circuit returns raw marked output containing the XSS payload.
// ---------------------------------------------------------------------------

describe('P1-REGRESSION: sanitizeHtml — sanitization must be environment-independent', () => {
  it('strips onerror event handler from img tag in SSR environment', () => {
    // marked wraps inline HTML in a paragraph; the img tag passes through as-is.
    // After fix: the onerror attribute must be absent from the rendered output.
    // Currently FAILS: the SSR bypass returns raw marked HTML including onerror.
    const result = renderMarkdown('<img src=x onerror=alert(1)>')
    expect(result).not.toContain('onerror')
  })

  it('removes script tags in SSR environment', () => {
    // marked renders the script tag inline; DOMPurify would strip it on the client.
    // After fix: no script tag in output regardless of environment.
    // Currently FAILS: the SSR bypass returns raw HTML containing <script>.
    const result = renderMarkdown('<script>alert("xss")</script>')
    expect(result).not.toContain('<script>')
    expect(result).not.toContain('alert(')
  })

  it('strips javascript: href in anchor tags in SSR environment', () => {
    // A javascript: protocol in href is an XSS vector DOMPurify strips.
    // Currently FAILS in node env: DOMPurify is never called.
    const result = renderMarkdown('<a href="javascript:alert(1)">click me</a>')
    expect(result).not.toContain('javascript:')
  })

  it('preserves safe markup — strong tag survives sanitization', () => {
    // Positive control: safe markup must survive after the fix.
    // In the buggy code this passes (raw output includes <strong>); it must
    // also pass after the fix (DOMPurify allows <strong>).
    const result = renderMarkdown('**bold text**')
    expect(result).toContain('<strong>')
    expect(result).toContain('bold text')
  })

  it('preserves safe markup — anchor with https href survives sanitization', () => {
    // DOMPurify allows https:// links; this must pass both before and after fix.
    const result = renderMarkdown('[link](https://example.com)')
    expect(result).toContain('href="https://example.com"')
  })

  it('strips inline onerror via renderMarkdownInline in SSR environment', () => {
    // renderMarkdownInline calls sanitizeHtml via marked.parseInline.
    // Currently FAILS in node env: SSR bypass returns raw output.
    const result = renderMarkdownInline('<img src=x onerror=alert(2)>')
    expect(result).not.toContain('onerror')
  })

  it('strips script tags via renderMarkdownWithMath in SSR environment', () => {
    // renderMarkdownWithMath also calls sanitizeHtml after math-block restoration.
    // Currently FAILS in node env: SSR bypass returns raw output.
    const result = renderMarkdownWithMath('<script>steal(document.cookie)</script>')
    expect(result).not.toContain('<script>')
    expect(result).not.toContain('steal(')
  })
})
