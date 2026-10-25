import { describe, expect, test } from "bun:test"
import { baseUrl, displayName, parseProperties, resolveSettings } from "../src/settings"
import { createApigeeFetch, createTokenSource } from "../src/token"
import { ApigeePlugin } from "../src/index"

describe("settings", () => {
  test("AI Relay's config file is read, Java escapes and all", () => {
    const props = parseProperties([
      "#AI Relay configuration",
      "vertex.endpoint=my-gw.example.com",
      "apigee.token.url=https\\://auth.example.com/oauth/token",
      "apigee.client.secret=s3cr\\=t",
      "apigee.agents=gemini-3.8-flash,gemini-3.1-pro",
      "key\\ with\\ space : value",
      "long=first \\",
      "    second",
    ].join("\n"))
    expect(props["apigee.token.url"]).toBe("https://auth.example.com/oauth/token")
    expect(props["apigee.client.secret"]).toBe("s3cr=t")
    expect(props["key with space"]).toBe("value")
    expect(props["long"]).toBe("first second")
  })

  test("options beat environment beat AI Relay, and the stored secret beats all", () => {
    const airelay = {
      "vertex.endpoint": "relay-gw", "vertex.project": "relay-proj", "apigee.token.url": "https://relay/token",
      "apigee.client.id": "relay-id", "apigee.client.secret": "relay-secret", "apigee.agents": "gemini-3.8-flash, gemini-4-argon",
    }
    const env = { APIGEE_GATEWAY: "env-gw", APIGEE_CLIENT_SECRET: "env-secret" }
    const { settings, missing } = resolveSettings({ project: "opt-proj" }, env, "stored-secret", airelay)
    expect(missing).toEqual([])
    expect(settings.gateway).toBe("env-gw")
    expect(settings.project).toBe("opt-proj")
    expect(settings.clientId).toBe("relay-id")
    expect(settings.clientSecret).toBe("stored-secret")
    expect(settings.location).toBe("us-central1")
    expect(settings.models).toEqual(["gemini-3.8-flash", "gemini-4-argon"])
  })

  test("what is missing is named", () => {
    const { missing } = resolveSettings({}, {}, undefined, {})
    expect(missing.join(" ")).toContain("gateway")
    expect(missing.join(" ")).toContain("client secret")
  })

  test("the base URL is the Vertex publisher path on the gateway", () => {
    const s = { gateway: "my-gw.example.com", project: "p 1", location: "europe-west4", tokenUrl: "", clientId: "", clientSecret: "", models: [], apiVersion: "v1", baseUrl: "" }
    expect(baseUrl(s)).toBe("https://my-gw.example.com/v1/projects/p%201/locations/europe-west4/publishers/google")
    expect(baseUrl({ ...s, gateway: "http://localhost:8080/" })).toBe("http://localhost:8080/v1/projects/p%201/locations/europe-west4/publishers/google")
  })

  test("the API version is configurable, and a full base URL replaces the path", () => {
    const s = { gateway: "gw", project: "p", location: "l", tokenUrl: "", clientId: "", clientSecret: "", models: [], apiVersion: "v1beta1", baseUrl: "" }
    expect(baseUrl(s)).toBe("https://gw/v1beta1/projects/p/locations/l/publishers/google")
    expect(baseUrl({ ...s, baseUrl: "https://gw.example.com/genai/vertex/" })).toBe("https://gw.example.com/genai/vertex")
    expect(baseUrl({ ...s, baseUrl: "gw.example.com/ai/{version}/projects/{project}/locations/{location}/publishers/google" }))
      .toBe("https://gw.example.com/ai/v1beta1/projects/p/locations/l/publishers/google")
  })

  test("with a base URL, gateway and project are needed only where it names them", () => {
    const base = { tokenUrl: "https://a/t", clientId: "i" }
    expect(resolveSettings({ ...base, baseUrl: "https://gw/genai" }, {}, "s", {}).missing).toEqual([])
    expect(resolveSettings({ ...base, baseUrl: "https://gw/{project}" }, {}, "s", {}).missing.join()).toContain("project")
    expect(resolveSettings({ ...base, apiVersion: "/v1beta1/" }, {}, "s", {}).settings.apiVersion).toBe("v1beta1")
    expect(resolveSettings(base, { APIGEE_BASE_URL: "https://env/x" }, "s", {}).settings.baseUrl).toBe("https://env/x")
  })

  test("display names", () => {
    expect(displayName("gemini-3.8-flash")).toBe("Gemini 3.8 Flash")
    expect(displayName("gemini-3.1-pro-preview")).toBe("Gemini 3.1 Pro (preview)")
    expect(displayName("gemini-3.5-flash-lite")).toBe("Gemini 3.5 Flash-Lite")
    expect(displayName("corp-model")).toBe("corp-model")
  })
})

describe("token", () => {
  test("client credentials go as AI Relay sends them, and the token is cached until near expiry", async () => {
    const calls: { url: string; init: RequestInit }[] = []
    let clock = 0
    const fake = (async (url: string, init: RequestInit) => {
      calls.push({ url, init })
      return new Response(JSON.stringify({ access_token: `tok${calls.length}`, expires_in: 120 }))
    }) as unknown as typeof fetch
    const tokens = createTokenSource("https://auth.example.com/token", "id", "secret", fake, () => clock)
    expect(await tokens.token()).toBe("tok1")
    expect(calls[0].url).toBe("https://auth.example.com/token?grant_type=client_credentials")
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe(`Basic ${Buffer.from("id:secret").toString("base64")}`)
    expect(calls[0].init.method).toBe("POST")
    clock = 59_000
    expect(await tokens.token()).toBe("tok1")
    clock = 61_000
    expect(await tokens.token()).toBe("tok2")
  })

  test("concurrent requests share one token fetch", async () => {
    let n = 0
    const fake = (async () => { n++; await Bun.sleep(10); return new Response(JSON.stringify({ access_token: "t" })) }) as unknown as typeof fetch
    const tokens = createTokenSource("https://a/t", "i", "s", fake)
    await Promise.all([tokens.token(), tokens.token(), tokens.token()])
    expect(n).toBe(1)
  })

  test("a refused token request says so", async () => {
    const fake = (async () => new Response("nope", { status: 401 })) as unknown as typeof fetch
    expect(createTokenSource("https://a/t", "i", "s", fake).token()).rejects.toThrow("HTTP 401")
  })
})

describe("fetch", () => {
  test("the API key header is replaced by the bearer token, and a 401 refreshes once", async () => {
    const seen: Headers[] = []
    let first = true
    const upstream = (async (_url: string, init: RequestInit) => {
      seen.push(new Headers(init.headers))
      if (first) { first = false; return new Response("expired", { status: 401 }) }
      return new Response("ok")
    }) as unknown as typeof fetch
    let i = 0
    const tokens = { token: async () => `tok${++i}`, invalidate: () => {} }
    const f = createApigeeFetch(tokens, upstream)
    const res = await f("https://gw/v1/x", { method: "POST", headers: { "x-goog-api-key": "apigee", "content-type": "application/json" }, body: "{}" })
    expect(await res.text()).toBe("ok")
    expect(seen.length).toBe(2)
    expect(seen[0].get("x-goog-api-key")).toBeNull()
    expect(seen[0].get("authorization")).toBe("Bearer tok1")
    expect(seen[1].get("authorization")).toBe("Bearer tok2")
    expect(seen[1].get("content-type")).toBe("application/json")
  })
})

describe("plugin", () => {
  test("registers the provider with the gateway's models and the Vertex base URL", async () => {
    const hooks = await ApigeePlugin({} as any, {
      gateway: "gw.example.com", project: "proj", tokenUrl: "https://a/t", clientId: "i", models: ["gemini-3.8-flash"], airelay: false,
    })
    const config: any = { provider: { apigee: { models: { "gemini-3.8-flash": { name: "Mine" } } } } }
    await hooks.config!(config)
    const p = config.provider.apigee
    expect(p.npm).toBe("@ai-sdk/google")
    expect(p.models["gemini-3.8-flash"].name).toBe("Mine")
    expect(p.options.baseURL).toBe("https://gw.example.com/v1/projects/proj/locations/us-central1/publishers/google")
    expect(hooks.auth!.provider).toBe("apigee")
  })

  test("the loader hands @ai-sdk/google the gateway, a placeholder key and the token fetch", async () => {
    const hooks = await ApigeePlugin({} as any, { gateway: "gw", project: "p", tokenUrl: "https://a/t", clientId: "i", airelay: false })
    const opts = await hooks.auth!.loader!(async () => ({ type: "api", key: "the-secret" }) as any, {} as any)
    expect(opts.baseURL).toBe("https://gw/v1/projects/p/locations/us-central1/publishers/google")
    expect(opts.apiKey).toBe("apigee")
    expect(typeof opts.fetch).toBe("function")
  })

  test("the loader refuses to start without a secret, naming it", async () => {
    const hooks = await ApigeePlugin({} as any, { gateway: "gw", project: "p", tokenUrl: "https://a/t", clientId: "i", airelay: false })
    expect(hooks.auth!.loader!(async () => undefined as any, {} as any)).rejects.toThrow("client secret")
  })
})
