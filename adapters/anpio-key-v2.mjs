/** v2 transport for existing Node/ANP clients. Rust CLI authenticates daemon UID.
 * Request IDs belong to callers: never regenerate one on transport failure.
 * No password, key export, arbitrary bytes, redirect, or automatic retry API.
 */
import { execFile } from 'node:child_process'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
const execute = promisify(execFile)

export class AnpioKeyV2Client {
  constructor({ config = '/etc/anpio-key/service.json', binary = '/usr/local/libexec/anpio-key' } = {}) {
    this.config = config
    this.binary = binary
  }
  async request(request) {
    const dir = await mkdtemp(join(tmpdir(), 'keyd-v2-'))
    try {
      const file = join(dir, 'request.json')
      await writeFile(file, JSON.stringify(request), { mode: 0o600, flag: 'wx' })
      const { stdout } = await execute(this.binary, ['data', '--config', this.config, '--file', file], {
        timeout: 15000, maxBuffer: 65536,
      })
      const reply = JSON.parse(stdout)
      if (reply.version !== 2 || reply.code !== 'OK') throw new Error('invalid keyd v2 reply')
      return reply.data
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  }
  keys() { return this.request({ operation: 'LIST_AUTHORIZED_KEYS' }) }
  document(key_id) { return this.request({ operation: 'GET_DOCUMENT', key_id }) }
  status(request_id) { return this.request({ operation: 'GET_REQUEST_STATUS', request_id }) }
  grant(grant_id) { return this.request({ operation: 'GET_GRANT_STATUS', grant_id }) }
  async sign({ grant_id, request_id, method, url, headers = {}, body, nonce = null }) {
    if (!request_id || !grant_id) throw new Error('explicit grant_id and stable request_id required')
    const bytes = body === undefined ? undefined : Buffer.from(body)
    if (bytes && bytes.length > 16384) throw new Error('body exceeds v2 bound')
    const http = { method, url, headers,
      body: bytes === undefined ? { state: 'absent' } : { state: 'present', bytes: [...bytes] }, nonce }
    const status = await this.request({ operation: 'SIGN_HTTP', grant_id, request_id, http })
    if (status.state !== 'completed' || !status.result) {
      const error = new Error(`keyd request ${request_id}: ${status.state}`)
      error.requestId = request_id
      error.state = status.state
      throw error
    }
    // Send exactly the body and URL that the daemon signed.
    // Caller retains private application headers; the durable result contains
    // only generated headers and the profile's covered content-type.
    const outgoing = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
    for (const [name, value] of Object.entries(status.result.headers)) outgoing[name.toLowerCase()] = value
    return { ...status.result, headers: outgoing, method, body: bytes }
  }
  async fetch(input) {
    const signed = await this.sign(input)
    return fetch(signed.url, { method: signed.method, headers: signed.headers,
      body: signed.body, redirect: 'manual' })
  }
}

/** Adapter for the existing ANP keyd connector's signHttpRequest-shaped seam.
 * Lifecycle/registration stays with a separate trusted management client.
 */
export function anpioKeyV2Signer(client, grant_id) {
  return {
    async signHttpRequest(input) {
      return client.sign({ ...input, grant_id })
    },
  }
}

/** Drop-in AnpConnector for the existing anp-sdk createConfig([connector]).
 * Pass the SDK's subjectOf export and a durable request-ID
 * callback. Canonical URLs must already match the SDK's outgoing target.
 */
export function anpioKeyV2Connector({ client, grant_id, key_id, requestId, subjectOf }) {
  async function getIdentity(want = {}) {
    const { keys } = await client.keys()
    const key = keys.find(k => k.key_id === key_id)
    if (!key || (want.did && key.did !== want.did) || (want.kid && key.kid !== `${key.did}#${want.kid}`)) {
      throw new Error('authorized exact key unavailable')
    }
    const { document } = await client.document(key_id)
    const method = document.verificationMethod?.find(vm => vm.id === key.kid)
    if (document.id !== key.did || !method?.publicKeyMultibase) throw new Error('invalid authorized document')
    return { subject: subjectOf(key.did), did: key.did, keyid: key.kid,
      publicKey: { publicKeyMultibase: method.publicKeyMultibase }, didDocument: document }
  }
  return {
    id: 'keyd-v2', name: 'anpio-key v2', type: 'keyd', getIdentity,
    async isAvailable() { try { await getIdentity(); return true } catch { return false } },
    async signRequest(req) {
      if (req.successorDid != null) throw new Error('DID lifecycle requires trusted management')
      const identity = await getIdentity()
      const payload = { ...(req.extraBody ?? {}), nonce: req.nonce, did: identity.did, didDocument: identity.didDocument }
      if (req.handle != null) payload.handle = req.handle
      const body = JSON.stringify(payload)
      const signed = await client.sign({ grant_id, request_id: requestId(req), method: req.method.toUpperCase(),
        url: req.url, headers: { 'content-type': 'application/json' }, body, nonce: req.nonce })
      if (signed.url !== req.url) throw new Error('SDK target must use the canonical URL; query original request ID before retry')
      return { ...identity, body, headers: signed.headers }
    },
  }
}
