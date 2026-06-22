import { query } from '@anthropic-ai/claude-agent-sdk'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import type { Peer } from 'crossws'
import type { NormalizedMessage, ProviderFetchOptions } from '~/types'
import type { ProviderAdapter, ProviderQueryOptions, ProviderInfo } from './types'
import { normalizeSDKMessage } from '../messageNormalizer'
import { resolveClaudePath } from '../claudeDir'
import { safeClaudePath } from '../path-security'
import { parseFrontmatter } from '../frontmatter'
import { detectSdkSession, loadSdkSessionMessages } from '../sdkSessionStorage'
import { MODEL_ALIAS_KEY } from '../models'
import { DEFAULT_OUTPUT_STYLES } from '../defaultOutputStyles'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

async function getOutputStyleContent(id: string, projectDir?: string): Promise<{ content: string; keepCodingInstructions: boolean } | null> {
  // 1. Check built-in
  const defaultStyle = DEFAULT_OUTPUT_STYLES.find(s => s.id === id)
  if (defaultStyle) {
    return { 
      content: id === 'default' ? '' : defaultStyle.content, 
      keepCodingInstructions: defaultStyle.keepCodingInstructions 
    }
  }

  // 2. Check global files
  const globalPath = resolveClaudePath('output-styles', `${id}.md`)
  if (existsSync(globalPath)) {
    const raw = readFileSync(globalPath, 'utf-8')
    const { frontmatter, body } = parseFrontmatter<any>(raw)
    return { 
      content: body, 
      keepCodingInstructions: frontmatter['keep-coding-instructions'] === true || frontmatter.keepCodingInstructions === true
    }
  }

  // 3. Check project files
  if (projectDir) {
    const projectPath = join(projectDir, '.claude', 'output-styles', `${id}.md`)
    if (existsSync(projectPath)) {
      const raw = readFileSync(projectPath, 'utf-8')
      const { frontmatter, body } = parseFrontmatter<any>(raw)
      return { 
        content: body, 
        keepCodingInstructions: frontmatter['keep-coding-instructions'] === true || frontmatter.keepCodingInstructions === true
      }
    }
  }

  return null
}

// Store active query instances for interruption
interface QueryInstance {
  interrupt(): Promise<void>
  [Symbol.asyncIterator](): AsyncIterator<any>
  peerId: string
}

const activeQueries = new Map<string, QueryInstance>()

// Store pending permission approvals (Promise resolvers/rejectors keyed by permissionId)
interface PermissionResolver {
  resolve: (decision: { allow: boolean; message?: string; updatedInput?: any }) => void
  reject: (error: Error) => void
  peerId: string
}
const pendingPermissions = new Map<string, PermissionResolver>()

const PERMISSION_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes

/**
 * Cleanup function to abort queries and reject permissions for a specific peer
 */
export async function cleanupPeer(peerId: string): Promise<void> {
  console.log(`[ClaudeProvider] Cleaning up peer: ${peerId}`)

  // 1. Interrupt active queries for this peer
  for (const [sessionId, queryInstance] of activeQueries.entries()) {
    if (queryInstance.peerId === peerId) {
      console.log(`[ClaudeProvider] Interrupting query for session ${sessionId}`)
      try {
        await queryInstance.interrupt()
      } catch (e) {
        console.error(`[ClaudeProvider] Error interrupting query during cleanup:`, e)
      }
      activeQueries.delete(sessionId)
    }
  }

  // 2. Reject pending permissions for this peer
  for (const [permissionId, resolver] of pendingPermissions.entries()) {
    if (resolver.peerId === peerId) {
      console.log(`[ClaudeProvider] Rejecting permission ${permissionId} due to connection closed`)
      resolver.reject(new Error('IPC connection closed'))
      pendingPermissions.delete(permissionId)
    }
  }
}

/**
 * Map permission mode to SDK format
 */
function mapPermissionMode(mode?: string): string {
  switch (mode) {
    case 'default':
      return 'default'
    case 'skip':
      return 'bypassPermissions' // "Skip" means allow all actions
    case 'acceptEdits':
      return 'acceptEdits'
    case 'bypassPermissions':
      return 'bypassPermissions'
    case 'plan':
      return 'plan'
    default:
      return 'default' // Safe default — require explicit opt-in for bypassPermissions
  }
}

/**
 * Claude provider adapter implementation.
 * Follows the claudecodeui pattern:
 * - No custom storage writes — the SDK writes to ~/.claude/projects/ natively
 * - Always pass `resume: sessionId` for any real session ID
 * - Let the SDK decide whether to resume or start fresh (it knows its own sessions)
 */
export const claudeProvider: ProviderAdapter = {
  name: 'claude',

  async query(prompt: string, options: ProviderQueryOptions, ws: Peer): Promise<void> {
    let capturedSessionId: string | null = null
    let sessionCreatedSent = false
    let accumulatedText = ''
    let hasTextMessageFromResult = false

    try {
      // Prepare SDK options
      const sdkOptions: any = {
        cwd: options.workingDir || process.cwd(),
        permissionMode: mapPermissionMode(options.permissionMode),
        allowedTools: ['Read', 'Write', 'Edit', 'Glob', 'Grep', 'Bash'],
        maxTurns: 10,
        includePartialMessages: true,
      }

      // Add system prompt configuration
      let systemAppend = options.agentInstructions || ''
      let systemPreset: 'claude_code' | 'none' = 'claude_code'

      if (options.outputStyleId) {
        const style = await getOutputStyleContent(options.outputStyleId, options.workingDir)
        if (style) {
          if (style.content) {
            systemAppend += (systemAppend ? '\n\n' : '') + `Additional style/behavioral instructions:\n${style.content}`
          }
          if (style.keepCodingInstructions === false) {
            systemPreset = 'none'
          }
        }
      }

      if (systemAppend) {
        sdkOptions.systemPrompt = {
          type: 'preset',
          preset: systemPreset,
          append: systemAppend,
        }
      } else {
        sdkOptions.systemPrompt = {
          type: 'preset',
          preset: systemPreset,
        }
      }

      // claudecodeui pattern: always pass resume if there's a real session ID.
      const isRealSessionId = options.sessionId && !options.sessionId.startsWith('new-session-')
      if (isRealSessionId) {
        sdkOptions.resume = options.sessionId
        capturedSessionId = options.sessionId ?? null
        console.log('[ClaudeProvider] Resuming SDK session:', options.sessionId)
      } else {
        console.log('[ClaudeProvider] Starting new SDK session')
      }

      // Add model if specified
      if (options.model) {
        sdkOptions.model = options.model
      }

      // Add effort level (controls thinking depth)
      if (options.effort) {
        sdkOptions.effort = options.effort
      }

      // Permission handling
      const permissionMode = sdkOptions.permissionMode
      if (permissionMode !== 'bypassPermissions') {
        sdkOptions.canUseTool = async (toolName: string, input: any) => {
          const isAllowed = (sdkOptions.allowedTools || []).some((t: string) => t === toolName)
          if (isAllowed) {
            return { behavior: 'allow', updatedInput: input }
          }

          const permissionId = randomUUID()
          const sessionId = capturedSessionId || options.sessionId || 'unknown'

          sendMessage(ws, {
            kind: 'permission_request',
            id: permissionId,
            sessionId,
            timestamp: new Date().toISOString(),
            requestId: permissionId,
            toolName,
            toolInput: input,
            content: `Allow ${toolName}?`,
            provider: 'claude',
          })

          try {
            const decision = await new Promise<{ allow: boolean; message?: string; updatedInput?: any }>((resolve, reject) => {
              pendingPermissions.set(permissionId, { resolve, reject, peerId: ws.id })

              setTimeout(() => {
                if (pendingPermissions.has(permissionId)) {
                  pendingPermissions.delete(permissionId)
                  resolve({ allow: false, message: 'Permission request timed out' })

                  sendMessage(ws, {
                    kind: 'permission_cancelled',
                    id: randomUUID(),
                    sessionId,
                    timestamp: new Date().toISOString(),
                    requestId: permissionId,
                    content: 'Permission request timed out',
                    provider: 'claude',
                  })
                }
              }, PERMISSION_TIMEOUT_MS)
            })

            if (decision.allow) {
              return { behavior: 'allow', updatedInput: decision.updatedInput || input }
            }
            return { behavior: 'deny', message: decision.message || 'User denied tool use' }
          } catch (error: any) {
            // This happens if cleanupPeer rejects the promise
            return { behavior: 'deny', message: error.message || 'Connection closed' }
          }
        }
      }

      const queryInstance = query({
        prompt,
        options: sdkOptions,
      })

      // Stream responses
      for await (const message of queryInstance) {
        if (message.session_id && !capturedSessionId) {
          capturedSessionId = message.session_id
          const extendedInstance = queryInstance as QueryInstance
          extendedInstance.peerId = ws.id
          activeQueries.set(capturedSessionId, extendedInstance)

          if (!sessionCreatedSent) {
            sessionCreatedSent = true
            sendMessage(ws, {
              kind: 'session_created',
              id: randomUUID(),
              sessionId: capturedSessionId,
              timestamp: new Date().toISOString(),
              content: capturedSessionId,
              newSessionId: capturedSessionId,
              provider: 'claude',
              metadata: {
                workingDir: options.workingDir || process.cwd(),
              },
            })
          }
        } else if (isRealSessionId && capturedSessionId && !activeQueries.has(capturedSessionId)) {
          const extendedInstance = queryInstance as QueryInstance
          extendedInstance.peerId = ws.id
          activeQueries.set(capturedSessionId, extendedInstance)
        }

        const normalized = normalizeSDKMessage(message, capturedSessionId || 'unknown')

        for (const msg of normalized) {
          const msgWithProvider: NormalizedMessage = {
            ...msg,
            provider: 'claude',
          }
          sendMessage(ws, msgWithProvider)

          if (msg.kind === 'stream_delta' && msg.content) {
            accumulatedText += msg.content
          }

          if (msg.kind === 'text' && msg.role === 'assistant') {
            hasTextMessageFromResult = true
          }
        }
      }

      const completeMsg: NormalizedMessage = {
        kind: 'complete',
        id: randomUUID(),
        sessionId: capturedSessionId || 'unknown',
        timestamp: new Date().toISOString(),
        content: '',
        provider: 'claude',
      }
      sendMessage(ws, completeMsg)
    } catch (error: any) {
      console.error('[ClaudeProvider] Error:', error)

      const errorMsg: NormalizedMessage = {
        kind: 'error',
        id: randomUUID(),
        sessionId: capturedSessionId || 'unknown',
        timestamp: new Date().toISOString(),
        content: error.message || 'An error occurred',
        provider: 'claude',
      }
      sendMessage(ws, errorMsg)
    } finally {
      if (capturedSessionId) {
        activeQueries.delete(capturedSessionId)
      }
    }
  },

  async respondToPermission(permissionId: string, decision: 'allow' | 'deny', updatedInput?: any): Promise<void> {
    const pending = pendingPermissions.get(permissionId)
    if (pending) {
      pendingPermissions.delete(permissionId)
      pending.resolve({
        allow: decision === 'allow',
        message: decision === 'deny' ? 'User denied tool use' : undefined,
        updatedInput,
      })
      console.log(`[ClaudeProvider] Permission ${permissionId} resolved: ${decision}`)
    } else {
      console.warn(`[ClaudeProvider] No pending permission found for ${permissionId}`)
    }
  },

  async interrupt(sessionId: string): Promise<boolean> {
    const queryInstance = activeQueries.get(sessionId)
    if (queryInstance) {
      try {
        await queryInstance.interrupt()
        activeQueries.delete(sessionId)
        return true
      } catch (error) {
        console.error('[ClaudeProvider] Error interrupting query:', error)
        return false
      }
    }
    return false
  },

  normalizeMessage(raw: any, sessionId: string): NormalizedMessage[] {
    return normalizeSDKMessage(raw, sessionId)
  },

  async fetchHistory(sessionId: string, options: ProviderFetchOptions) {
    const projectName = await detectSdkSession(sessionId)
    if (projectName) {
      const result = await loadSdkSessionMessages(projectName, sessionId, {
        limit: options.limit ?? 50,
        offset: options.offset ?? 0,
      })
      return {
        messages: result.messages as NormalizedMessage[],
        total: result.total,
        hasMore: result.hasMore,
      }
    }

    return {
      messages: [],
      total: 0,
      hasMore: false,
    }
  },

  async loadAgentInstructions(agentSlug: string): Promise<string | null> {
    try {
      const agentPath = safeClaudePath('agents', `${agentSlug}.md`)
      const content = await fs.readFile(agentPath, 'utf-8')
      const { body } = parseFrontmatter(content)
      return body || null
    } catch (error) {
      console.error(`[ClaudeProvider] Failed to load agent ${agentSlug}:`, error)
      return null
    }
  },
}

function sendMessage(ws: Peer, message: NormalizedMessage): void {
  try {
    ws.send(JSON.stringify(message))
  } catch (error) {
    console.error('[ClaudeProvider] Error sending message:', error)
  }
}

export const claudeProviderInfo: ProviderInfo = {
  name: 'claude',
  displayName: 'Claude',
  description: 'Anthropic Claude via Claude Agent SDK',
  models: Object.values(MODEL_ALIAS_KEY),
  supportsPermissions: true,
  supportsImages: true,
  supportsInterrupt: true,
}
