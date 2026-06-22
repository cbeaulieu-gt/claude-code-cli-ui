/**
 * Vitest global setup — stubs Nuxt auto-imports unavailable in the test environment.
 *
 * `createError` is a Nuxt H3 global injected at runtime. Under vitest there is
 * no Nuxt context, so production modules that call it (path-security, claudeDir)
 * would throw `ReferenceError: createError is not defined` before any assertion
 * could run. We provide a minimal stub that produces a plain Error with the same
 * shape the production code expects.
 */

interface CreateErrorOptions {
  statusCode?: number
  message?: string
}

globalThis.createError = (options: CreateErrorOptions | string): Error => {
  const opts: CreateErrorOptions = typeof options === 'string' ? { message: options } : options
  const err = new Error(opts.message ?? 'error') as Error & { statusCode?: number }
  err.statusCode = opts.statusCode
  return err
}
