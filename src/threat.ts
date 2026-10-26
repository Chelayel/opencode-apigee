/**
 * Apigee's threat-protection policies (RegularExpressionProtection,
 * JSONThreatProtection, …) refuse a request body containing `<script>`, SQL
 * and the like with a 400 or 403, before it reaches Vertex. Coding requests
 * trip them all the time, and the gateway's settings are often not the user's
 * to change.
 *
 * What passes is what the scan cannot read: the user's text and tool output as
 * base64 `text/plain` attachments (`inlineData`), which Vertex decodes and the
 * model reads as documents. The model's own earlier turns go back as they came
 * (their thought signatures depend on it), so a block caused by the model's
 * words cannot be worked around this way. Same behaviour as AI Relay's
 * `apigee.encode.text`.
 */

export type EncodeMode = "auto" | "always" | "never"

export function encodeMode(value: string | undefined): EncodeMode {
  const v = value?.trim().toLowerCase()
  if (v === "always" || v === "true" || v === "on" || v === "yes") return "always"
  if (v === "never" || v === "false" || v === "off" || v === "no") return "never"
  return "auto"
}

/** The refusing policy, when a 400/403 body is an Apigee threat-protection fault; else null. */
export function detectThreat(status: number, body: string): string | null {
  if (status !== 400 && status !== 403) return null
  let code = ""
  let text = body
  try {
    const fault = JSON.parse(body)?.fault
    code = typeof fault?.detail?.errorcode === "string" ? fault.detail.errorcode : ""
    if (typeof fault?.faultstring === "string") text = fault.faultstring
  } catch {
    /* not JSON: look at the text */
  }
  const threat = /threatprotection|regularexpressionprotection|threat detected|ThreatDetected/i
  if (!threat.test(code) && !threat.test(text)) return null
  // The faultstring quotes the regex and the matched input — the user's code — so only its head is kept.
  const said = text.split(" input:")[0].split(" regex:")[0].trim().slice(0, 160)
  return [code, said].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(": ") || "threat protection"
}

export const NOTE =
  "(The text of this turn — the user's message and any tool output — is attached as text/plain documents " +
  "so it passes a filter on the way. Read each one as if it were written here.)"

const toDoc = (text: string) => ({ inlineData: { mimeType: "text/plain", data: Buffer.from(text, "utf8").toString("base64") } })

/** A `generateContent` body with the user's side carried as documents; the model's turns untouched. */
export function encodeBody(body: string): string {
  const req = JSON.parse(body)
  if (!Array.isArray(req.contents)) return body
  req.contents = req.contents.map((c: any) => {
    if (c?.role !== "user" || !Array.isArray(c.parts)) return c
    const calls: any[] = []
    const attached: any[] = []
    let changed = false
    for (const p of c.parts) {
      if (typeof p?.text === "string") {
        attached.push(toDoc(p.text))
        changed = true
      } else if (p?.functionResponse) {
        const response = p.functionResponse.response ?? {}
        const values = Object.values(response)
        const output = values.length === 1 && typeof values[0] === "string" ? (values[0] as string) : JSON.stringify(response)
        calls.push({ ...p, functionResponse: { ...p.functionResponse, response: { content: "(The output is attached below as a text document.)" } } })
        attached.push(toDoc(output))
        changed = true
      } else attached.push(p)
    }
    return changed ? { ...c, parts: [...calls, { text: NOTE }, ...attached] } : c
  })
  return JSON.stringify(req)
}

export function threatMessage(policy: string, status: number, mode: EncodeMode, retriedEncoded: boolean): string {
  const head = `The Apigee gateway's threat protection refused the request (HTTP ${status}, ${policy}).`
  if (mode === "never")
    return `${head} It scans requests for things like <script> tags or SQL. Set encodeText to "auto" (APIGEE_ENCODE_TEXT) to re-send a blocked request with your text and tool output base64-encoded, which the scan cannot read.`
  if (retriedEncoded)
    return `${head} It was re-sent with your text and tool output base64-encoded and still refused: what it objects to is probably in the model's own earlier replies or tool calls, which must go back as they were. Start a new session to leave them behind.`
  return `${head} It scans requests for things like <script> tags or SQL.`
}
