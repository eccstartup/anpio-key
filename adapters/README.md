# v2 client and existing ANP SDK connector

Node 18+ imports `AnpioKeyV2Client` from `anpio-key-v2.mjs`. The administrator supplies the
service config, grant and exact key handle. The Rust CLI authenticates the daemon.
Persist request IDs with their payload before calling `sign`; on uncertain
transport outcomes query `status` with that ID. Do not auto-generate another ID.
`fetch` sends only the daemon's canonical URL, original body and returned headers,
with manual redirects. There is no password, raw signing, lifecycle, or downgrade.

For the existing `@connectx-sdk/core` API:

```js
import { createConfig, signRequest, subjectOf } from '@connectx-sdk/core'
import { AnpioKeyV2Client, anpioKeyV2Connector } from './anpio-key-v2.mjs'
const client = new AnpioKeyV2Client()
const connector = anpioKeyV2Connector({ client, grant_id, key_id, subjectOf,
  requestId: req => durableRequestIdForThisExactPayload(req) })
const config = createConfig([connector])
const signed = await signRequest(config, connector.id, {
  method: 'POST', url: canonicalUrl, nonce: serverNonce,
})
```

Supply a stable request-ID function backed by your durable operation state.
The connector rejects successor/lifecycle operations. Registration challenge
proofs go through a distinct trusted management client. Existing SDK transport
must use canonical targets and disable redirects; the connector refuses a
noncanonical target after signing and requires querying the original ID.

`test-sdk.mjs SDK_DIST GRANT KEY REQUEST_ID RPC_REQUEST_ID` is the live Linux acceptance driver;
it runs the existing SDK's `createConfig` and `signRequest` under an Agent UID,
verifies same-ID result reuse, and prints a request for the real service harness.
External SDK sources are read-only test inputs, not vendored or modified here.

Compatibility boundary: anp-sdk signRequest produces an ANP-02 login body; awiki did-auth RPC requires a JSON-RPC envelope. The live acceptance verifies the former with the existing SDK verifier and nonce store, and uses the same v2 client with the actual JSON-RPC body for awiki. It does not rewrite already-signed bytes or claim a native SDK login endpoint exists on awiki.

Hot-key resolution requires `@connectx-sdk/core` 0.4.2 or later. A root-signed
active document authorizes the exact authentication
method; the DID fingerprint binds the proof key rather than every hot key.
Older SDK builds still reject legitimate hot methods. There is no root-key fallback.

`test-sdk.mjs` requires `resolveVerificationKey` and `verifyAnpLoginRequest`
to succeed without a supplied public key, and checks replay, wrong nonce and body
tampering. The SDK's own tests cover wrong kid, withheld authentication, forged
root proof, expiry, relative methods, network resolution and key substitution.
Set `ANPIO_KEY_TEST_SDK` to the rebuilt SDK's absolute `dist/index.js` path in the
Linux boundary harness to exercise this under an independent Agent UID without
requiring an external ANP service. Use Node 22.12+ for SDK integration (the standalone
v2 client supports Node 18+). The service-specific RPC envelope remains separate
from ANP-02; this local verification does not assert a remote business result.
