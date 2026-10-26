// Optional live acceptance: Node runs under a real independent Linux Agent UID.
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { AnpioKeyV2Client, anpioKeyV2Connector } from './anpio-key-v2.mjs'
const [sdkPath, grant_id, key_id, request_id, rpc_request_id] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath))
const client = new AnpioKeyV2Client()
const connector = anpioKeyV2Connector({ client, grant_id, key_id, requestId: () => request_id, subjectOf: sdk.subjectOf })
const config = sdk.createConfig([connector])
const request = { method: 'POST', url: 'https://example.com/user-service/v1/did-auth/rpc', nonce: request_id,
  extraBody: { jsonrpc: '2.0', id: request_id, method: 'get_me', params: {} } }
const first = await sdk.signRequest(config, connector.id, request)
assert(first.keyid.includes('#http-'))
assert(first.headers['Signature'] || first.headers.signature)
const second = await sdk.signRequest(config, connector.id, request)
assert.deepEqual(second, first, 'persisted request ID must return identical headers and body')
const status = await client.status(request_id)
assert.equal(status.state, 'completed')
assert.equal((await client.grant(grant_id)).used_uses, 1)
await assert.rejects(connector.signRequest({ ...request, successorDid: 'did:wba:other.example' }), /management/)
sdk.verifyDidDocument(first.didDocument, first.did)
assert(first.didDocument.authentication.includes(first.keyid))
const resolved = await sdk.resolveVerificationKey(first.keyid, first.didDocument)
assert.deepEqual(resolved.bytes, sdk.decodeMultibaseKey(first.publicKey.publicKeyMultibase).bytes)
const verification = {
  method: 'POST', path: '/user-service/v1/did-auth/rpc', authority: 'example.com', targetUri: request.url,
  headers: Object.fromEntries(Object.entries(first.headers).map(([k, v]) => [k.toLowerCase(), v])),
  body: first.body, expectedNonce: request_id, nonceStore: sdk.createNonceStore(),
}
assert.equal((await sdk.verifyAnpLoginRequest(verification)).ok, true, 'high-level SDK resolves and verifies actual keyd hot signature')
assert.equal((await sdk.verifyAnpLoginRequest(verification)).ok, false, 'high-level SDK rejects replay')
assert.equal((await sdk.verifyAnpLoginRequest({ ...verification, nonceStore: sdk.createNonceStore(),
  body: JSON.stringify({ ...JSON.parse(first.body), handle: 'injected' }) })).ok, false, 'high-level SDK rejects replaced body')
assert.equal((await sdk.verifyAnpLoginRequest({ ...verification, nonceStore: sdk.createNonceStore(),
  expectedNonce: 'wrong-challenge' })).ok, false, 'high-level SDK rejects wrong server nonce')
const sdkHotResolverSupported = true
// awiki's RPC accepts JSON-RPC bodies, not the SDK's ANP-02 login body.
// Use the v2 structured HTTP client with its actual service envelope.
assert(rpc_request_id, 'caller must persist a distinct ID for the RPC payload')
const body = JSON.stringify({ jsonrpc: '2.0', id: rpc_request_id, method: 'get_me', params: {} })
const rpc = await client.sign({ grant_id, request_id: rpc_request_id, method: 'POST', url: request.url,
  headers: { 'content-type': 'application/json' }, body, nonce: rpc_request_id })
console.log(JSON.stringify({ body, headers: rpc.headers, sdkProtocolVerified: true, sdkHotResolverSupported }))
