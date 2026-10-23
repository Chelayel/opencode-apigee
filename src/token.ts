/**
 * The Apigee OAuth token: client credentials, sent the way AI Relay sends them
 * (`grant_type=client_credentials` on the token URL, HTTP Basic with the client
 * id and secret, empty body), cached until a minute before it expires.
 */
export interface TokenSource {
  token(): Promise<string>
  /** Forget the cached token, after the gateway refused it. */
  invalidate(): void
}

export function createTokenSource(
  tokenUrl: string,
  clientId: string,
  clientSecret: string,
  fetchImpl: typeof fetch = fetch,
  now: () => number = Date.now,
): TokenSource {
  let cached: { token: string; expiresAt: number } | undefined
  let pending: Promise<string> | undefined

  async function request(): Promise<string> {
    const url = tokenUrl + (tokenUrl.includes("?") ? "&" : "?") + "grant_type=client_credentials"
    const basic = Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64")
    const res = await fetchImpl(url, {
      method: "POST",
      headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    })
    if (!res.ok) throw new Error(`Apigee token request failed (HTTP ${res.status}). Check the token URL, client id and secret.`)
    const body = (await res.json().catch(() => ({}))) as { access_token?: unknown; expires_in?: unknown }
    if (typeof body.access_token !== "string" || !body.access_token) throw new Error("Apigee token response had no access_token.")
    const expiresIn = Number(body.expires_in) > 0 ? Number(body.expires_in) : 3600
    cached = { token: body.access_token, expiresAt: now() + Math.max(30, expiresIn - 60) * 1000 }
    return body.access_token
  }

  return {
    async token() {
      if (cached && cached.expiresAt > now()) return cached.token
      // Concurrent requests share one token fetch rather than racing several.
      pending ??= request().finally(() => (pending = undefined))
      return pending
    },
    invalidate() {
      cached = undefined
    },
  }
}

/**
 * A fetch for `@ai-sdk/google` aimed at the gateway: its `x-goog-api-key`
 * header is replaced by the Apigee bearer token. A 401 means the token went
 * stale early (rotated, revoked): it is fetched again and the request retried
 * once.
 */
export function createApigeeFetch(tokens: TokenSource, baseFetch: typeof fetch = fetch): typeof fetch {
  const send = async (input: Parameters<typeof fetch>[0], init: RequestInit | undefined) => {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined))
    headers.delete("x-goog-api-key")
    headers.set("Authorization", `Bearer ${await tokens.token()}`)
    return baseFetch(input, { ...init, headers })
  }
  const apigeeFetch = async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const res = await send(input, init)
    if (res.status !== 401) return res
    tokens.invalidate()
    return send(input, init)
  }
  return apigeeFetch as typeof fetch
}
