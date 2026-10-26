import { describe, expect, test } from "bun:test"
import { createApigeeFetch } from "../src/token"
import { detectThreat, encodeBody } from "../src/threat"

const FAULT = JSON.stringify({ fault: { faultstring: "Regular Expression Threat Detected in RE: regex: .*<script>.* input: <script>x</script>", detail: { errorcode: "steps.regularexpressionprotection.ThreatDetected" } } })

/** A gateway that refuses any body with <script> in it, as RegularExpressionProtection does. */
function gateway() {
  const bodies: string[] = []
  const f = (async (_url: string, init: RequestInit) => {
    const body = String(init.body ?? "")
    bodies.push(body)
    if (body.includes("<script>")) return new Response(FAULT, { status: 403 })
    return new Response("data: {}\n\n", { headers: { "Content-Type": "text/event-stream" } })
  }) as unknown as typeof fetch
  return { f, bodies }
}
const tokens = { token: async () => "tok", invalidate: () => {} }
const request = (text: string) => ({ method: "POST", body: JSON.stringify({ contents: [{ role: "user", parts: [{ text }] }] }) })

describe("threat protection", () => {
  test("auto re-sends a refused request encoded, then encodes from the start", async () => {
    const g = gateway()
    const f = createApigeeFetch(tokens, g.f, "auto")
    expect((await f("https://gw/x", request("why <script>x</script>?"))).status).toBe(200)
    expect(g.bodies.length).toBe(2)
    expect(g.bodies[1]).not.toContain("<script>")
    expect(g.bodies[1]).toContain('"mimeType":"text/plain"')
    await f("https://gw/x", request("again <script>y</script>"))
    expect(g.bodies.length).toBe(3)
  })

  test("never returns a readable error in Google's shape, without the matched input", async () => {
    const g = gateway()
    const res = await createApigeeFetch(tokens, g.f, "never")("https://gw/x", request("<script>x</script>"))
    expect(res.status).toBe(403)
    const msg = (await res.json()).error.message as string
    expect(msg).toContain("threat protection")
    expect(msg).toContain("APIGEE_ENCODE_TEXT")
    expect(msg).not.toContain("<script>x</script>")
    expect(g.bodies.length).toBe(1)
  })

  test("the model's own words stay as they are, and the error says to start a new session", async () => {
    const g = gateway()
    const body = JSON.stringify({ contents: [
      { role: "user", parts: [{ text: "write a page" }] },
      { role: "model", parts: [{ text: "<script>go()</script>" }] },
      { role: "user", parts: [{ text: "thanks" }] },
    ] })
    const res = await createApigeeFetch(tokens, g.f, "auto")("https://gw/x", { method: "POST", body })
    expect(res.status).toBe(403)
    expect((await res.json()).error.message).toContain("new session")
  })

  test("encoding carries text and tool output as documents, model turns untouched", () => {
    const out = JSON.parse(encodeBody(JSON.stringify({ contents: [
      { role: "model", parts: [{ functionCall: { name: "read", args: { path: "a.html" } }, thoughtSignature: "sig" }] },
      { role: "user", parts: [{ functionResponse: { name: "read", response: { content: "<script>x()</script>" } } }] },
    ] })))
    expect(out.contents[0].parts[0].thoughtSignature).toBe("sig")
    const parts = out.contents[1].parts
    expect(parts[0].functionResponse.response.content).not.toContain("<script>")
    const doc = parts.find((p: any) => p.inlineData).inlineData
    expect(Buffer.from(doc.data, "base64").toString()).toBe("<script>x()</script>")
  })

  test("only threat-protection faults are recognised", () => {
    expect(detectThreat(400, JSON.stringify({ error: { message: "Invalid argument" } }))).toBeNull()
    expect(detectThreat(500, FAULT)).toBeNull()
    expect(detectThreat(403, FAULT)).toContain("steps.regularexpressionprotection.ThreatDetected")
  })
})
