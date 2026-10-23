import type { Plugin } from "@opencode-ai/plugin"
import { baseUrl, displayName, resolveSettings, type ApigeeOptions } from "./settings.js"
import { createApigeeFetch, createTokenSource } from "./token.js"

// Only the plugin is exported: OpenCode treats exported functions as plugins.

/** What a Gemini model on Vertex can do; a gateway id OpenCode cannot look up gets these. */
const GEMINI_LIMITS = { context: 1_048_576, output: 65_536 }

/**
 * Gemini on Vertex AI behind an Apigee gateway, as an OpenCode provider.
 *
 * The provider is `@ai-sdk/google` aimed at the gateway's Vertex publisher
 * path: its request URL is then Vertex's own, and the body is the same
 * `generateContent` JSON. What differs is the credential — an OAuth token from
 * the gateway's client-credentials endpoint instead of a Google API key — and
 * that is the whole of this plugin: a fetch that swaps the one for the other.
 * The client secret is OpenCode's to keep (`opencode auth login` → Apigee).
 */
export const ApigeePlugin: Plugin = async (_input, rawOptions) => {
  const options = (rawOptions ?? {}) as ApigeeOptions
  const providerId = options.providerId?.trim() || "apigee"

  return {
    config: async (config) => {
      const { settings } = resolveSettings(options)
      const models: Record<string, any> = {}
      for (const id of settings.models) {
        models[id] = {
          name: displayName(id),
          tool_call: true,
          attachment: true,
          reasoning: /gemini-([3-9]|2\.5)/.test(id),
          limit: GEMINI_LIMITS,
          modalities: { input: ["text", "image", "pdf"], output: ["text"] },
        }
      }
      config.provider ??= {}
      const existing = (config.provider[providerId] ?? {}) as Record<string, any>
      config.provider[providerId] = {
        name: options.name?.trim() || "Gemini via Apigee",
        npm: "@ai-sdk/google",
        ...existing,
        // A model the user described in opencode.json keeps their description.
        models: { ...models, ...(existing.models ?? {}) },
        options: {
          ...(settings.gateway && settings.project ? { baseURL: baseUrl(settings) } : {}),
          ...(existing.options ?? {}),
        },
      }
    },

    auth: {
      provider: providerId,
      methods: [
        {
          type: "api",
          label: "Apigee client secret",
        },
      ],
      loader: async (getAuth) => {
        const stored = await getAuth().catch(() => undefined)
        const secret = stored && stored.type === "api" ? stored.key : undefined
        const { settings, missing } = resolveSettings(options, process.env, secret)
        if (missing.length) throw new Error(`opencode-apigee: missing ${missing.join(", ")}.`)
        const tokens = createTokenSource(settings.tokenUrl, settings.clientId, settings.clientSecret)
        return {
          baseURL: baseUrl(settings),
          // Required by @ai-sdk/google and never sent: the fetch replaces it with the token.
          apiKey: "apigee",
          fetch: createApigeeFetch(tokens),
        }
      },
    },
  }
}
