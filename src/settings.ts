import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

/** Everything needed to reach Gemini on Vertex AI through an Apigee gateway. */
export interface ApigeeSettings {
  /** Gateway base, e.g. `https://my-gw.example.com`; a bare host gets `https://`. */
  gateway: string
  project: string
  location: string
  tokenUrl: string
  clientId: string
  clientSecret: string
  /** Model ids the gateway publishes. */
  models: string[]
  /** Vertex API version in the path (default `v1`). */
  apiVersion: string
  /** `auto` (re-send a request threat protection refused, encoded), `always` or `never`. */
  encodeText: string
  /**
   * The whole base URL — everything before `/models/<id>:…` — used instead of the
   * standard path, for a gateway that does not mount Vertex the standard way.
   * May use `{project}`, `{location}` and `{version}`.
   */
  baseUrl: string
}

/** Plugin options, as written in opencode.json: `["opencode-apigee", { ... }]`. */
export interface ApigeeOptions {
  gateway?: string
  project?: string
  location?: string
  tokenUrl?: string
  clientId?: string
  clientSecret?: string
  models?: string[] | string
  /** Vertex API version in the path, e.g. `v1beta1` (default `v1`). */
  apiVersion?: string
  /** Full base URL up to `/models`, replacing the standard path; may use `{project}`, `{location}`, `{version}`. */
  baseUrl?: string
  /** Threat protection: `auto` (default) re-sends a refused request with text as base64 documents; `always`; `never`. */
  encodeText?: string
  /** Provider id in OpenCode (default `apigee`). */
  providerId?: string
  /** Display name in OpenCode (default `Gemini via Apigee`). */
  name?: string
  /** Read settings from AI Relay's config file when not given here (default true). */
  airelay?: boolean
}

/**
 * Settings from, in order: the secret OpenCode stored (`opencode auth login`),
 * plugin options, `APIGEE_*` environment variables, and AI Relay's
 * `~/.airelay/config.properties` — so someone already set up with
 * `airelay gemini setup` only adds the plugin.
 */
export function resolveSettings(
  options: ApigeeOptions = {},
  env: Record<string, string | undefined> = process.env,
  storedSecret?: string,
  airelay: Record<string, string> = options.airelay === false ? {} : readAirelayConfig(env),
): { settings: ApigeeSettings; missing: string[] } {
  const pick = (opt: string | undefined, envKey: string, airelayKey: string) =>
    nonBlank(opt) ?? nonBlank(env[envKey]) ?? nonBlank(airelay[airelayKey])

  const models = list(options.models) ?? list(env.APIGEE_MODELS) ?? list(airelay["apigee.agents"]) ?? list(airelay["gemini.model"]) ?? []
  const settings: ApigeeSettings = {
    gateway: pick(options.gateway, "APIGEE_GATEWAY", "vertex.endpoint") ?? "",
    project: pick(options.project, "APIGEE_PROJECT", "vertex.project") ?? nonBlank(env.GOOGLE_CLOUD_PROJECT) ?? "",
    location: pick(options.location, "APIGEE_LOCATION", "vertex.location") ?? "us-central1",
    tokenUrl: pick(options.tokenUrl, "APIGEE_TOKEN_URL", "apigee.token.url") ?? "",
    clientId: pick(options.clientId, "APIGEE_CLIENT_ID", "apigee.client.id") ?? "",
    clientSecret: nonBlank(storedSecret) ?? pick(options.clientSecret, "APIGEE_CLIENT_SECRET", "apigee.client.secret") ?? "",
    models,
    apiVersion: pick(options.apiVersion, "APIGEE_API_VERSION", "vertex.api.version")?.replace(/^\/+|\/+$/g, "") ?? "v1",
    baseUrl: pick(options.baseUrl, "APIGEE_BASE_URL", "vertex.base.url") ?? "",
    encodeText: pick(options.encodeText, "APIGEE_ENCODE_TEXT", "apigee.encode.text") ?? "auto",
  }
  const missing: string[] = []
  // With a full base URL, the gateway and project are only needed where it names them.
  const needs = (part: string) => !settings.baseUrl || settings.baseUrl.includes(`{${part}}`)
  if (!settings.baseUrl && !settings.gateway) missing.push("gateway (APIGEE_GATEWAY) or baseUrl (APIGEE_BASE_URL)")
  if (needs("project") && !settings.project) missing.push("project (APIGEE_PROJECT)")
  if (!settings.tokenUrl) missing.push("tokenUrl (APIGEE_TOKEN_URL)")
  if (!settings.clientId) missing.push("clientId (APIGEE_CLIENT_ID)")
  if (!settings.clientSecret) missing.push("client secret (`opencode auth login` → Apigee, or APIGEE_CLIENT_SECRET)")
  return { settings, missing }
}

/**
 * The Vertex publisher path on the gateway. `@ai-sdk/google` appends
 * `/models/<id>:streamGenerateContent`, which together is Vertex's own URL.
 * Gateways differ in version and in where they mount Vertex, so neither is
 * fixed: `apiVersion` changes the one, `baseUrl` replaces the whole path.
 */
export function baseUrl(s: ApigeeSettings): string {
  const fill = (t: string) => t
    .replaceAll("{project}", encodeURIComponent(s.project))
    .replaceAll("{location}", encodeURIComponent(s.location))
    .replaceAll("{version}", s.apiVersion)
  if (s.baseUrl) {
    const url = fill(s.baseUrl)
    return (/^https?:\/\//i.test(url) ? url : `https://${url}`).replace(/\/+$/, "")
  }
  const gateway = /^https?:\/\//i.test(s.gateway) ? s.gateway : `https://${s.gateway}`
  return `${gateway.replace(/\/+$/, "")}/${s.apiVersion}/projects/${encodeURIComponent(s.project)}/locations/${encodeURIComponent(s.location)}/publishers/google`
}

/** AI Relay's config file, or nothing. Its path follows AIRELAY_CONFIG like AI Relay itself. */
export function readAirelayConfig(env: Record<string, string | undefined> = process.env): Record<string, string> {
  const file = nonBlank(env.AIRELAY_CONFIG) ?? join(homedir(), ".airelay", "config.properties")
  try {
    return parseProperties(readFileSync(file, "utf8"))
  } catch {
    return {}
  }
}

/**
 * java.util.Properties text: `key=value` or `key:value`, `#`/`!` comments,
 * backslash escapes (`https\://…` is how Java writes a URL) and line
 * continuations.
 */
export function parseProperties(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].replace(/^\s+/, "")
    if (!line || line.startsWith("#") || line.startsWith("!")) continue
    while (/(^|[^\\])(\\\\)*\\$/.test(line) && i + 1 < lines.length) line = line.slice(0, -1) + lines[++i].replace(/^\s+/, "")
    let k = 0
    while (k < line.length && !"=: \t".includes(line[k])) k += line[k] === "\\" ? 2 : 1
    const key = unescape(line.slice(0, k))
    let rest = line.slice(k).replace(/^[ \t]*/, "")
    if (rest.startsWith("=") || rest.startsWith(":")) rest = rest.slice(1).replace(/^[ \t]*/, "")
    out[key] = unescape(rest)
  }
  return out
}

function unescape(s: string): string {
  return s.replace(/\\(u[0-9a-fA-F]{4}|.)/g, (_, c: string) => {
    if (c.length === 5) return String.fromCharCode(parseInt(c.slice(1), 16))
    return c === "t" ? "\t" : c === "n" ? "\n" : c === "r" ? "\r" : c === "f" ? "\f" : c
  })
}

function nonBlank(s: string | undefined): string | undefined {
  return s && s.trim() ? s.trim() : undefined
}

function list(v: string[] | string | undefined): string[] | undefined {
  const items = (Array.isArray(v) ? v : (v ?? "").split(",")).map((m) => m.trim()).filter(Boolean)
  return items.length ? [...new Set(items)] : undefined
}

/** `gemini-3.1-pro-preview` → "Gemini 3.1 Pro (preview)"; anything else as it is. */
export function displayName(id: string): string {
  if (!/^gemini-/i.test(id)) return id
  const words = id.split("-")
  const preview = words[words.length - 1].toLowerCase() === "preview"
  const name = (preview ? words.slice(0, -1) : words)
    .map((w) => (/^\d/.test(w) ? w : w.toLowerCase() === "lite" ? "Lite" : w[0].toUpperCase() + w.slice(1)))
    .join(" ")
    .replace("Flash Lite", "Flash-Lite")
  return preview ? `${name} (preview)` : name
}
