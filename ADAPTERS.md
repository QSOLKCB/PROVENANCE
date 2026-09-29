# PROVENANCE Phase 10 — Generic Adapter Interface

Phase 10 defines a provider-neutral adapter boundary without moving provider semantics into `provenance-core`.

~~~text
MODULE=provenance-adapters
CONTRACT=provider-neutral
CORE_SCHEMA_CHANGES=NONE
REFERENCE_ADAPTERS=generic-http,local-process
~~~

## Contract

Every Phase 10 adapter declares an `AdapterContract`:

~~~text
adapter_id
source_kind
observation_boundary
extension_namespace
~~~

The shared evidence translator accepts:

~~~text
input captures
output captures
declared metadata
extensions
failure state
~~~

and emits ordinary Phase 1 core records:

~~~text
ArtifactRecord
EventEnvelope
Relationship
CollectionStatus
~~~

Adapters are not permitted to add provider-specific fields to the universal event schema.

## Evidence classification

Exact payload bytes directly visible at the adapter boundary are emitted through `OBSERVED` events. Synthetic invocation/request descriptors are retained conservatively as `DECLARED` evidence, while operation-level completion summaries are `DERIVED`.

Examples:

~~~text
HTTP request body
HTTP response body
process stdin
process stdout
process stderr
~~~

Request/invocation descriptors and adapter/provider metadata are stored as retained artifacts referenced by `DECLARED` events.

This is intentionally conservative. A provider field does not become independently observed truth merely because an adapter can parse it.

Adapter-specific metadata lives under an explicit extension namespace such as:

~~~text
provenance.adapter.http
provenance.adapter.process
~~~

Extensions remain artifact content. They do not modify core schema semantics.

The reference adapters use one role-neutral `application/octet-stream` artifact media type for retained adapter bytes. Request/response/stdin/stdout roles live in events, which prevents identical bytes from being rebound to conflicting artifact metadata merely because their transport role differs.

## Generic HTTP adapter

`GenericHTTPAdapter` supports ordinary HTTP/HTTPS request-response observation.

It records:

~~~text
request descriptor
request body
response body or observed response prefix
HTTP status as declared adapter metadata
failure collection status when applicable
~~~

Redirects are not followed.

HTTP header values are runtime-only and are deliberately not retained as evidence. This prevents API keys, cookies, and authorization material from becoming ordinary evidence payloads merely because they were needed for transport.

`Content-Type`, `Content-Length`, `Host`, and `Transfer-Encoding` are adapter-controlled rather than caller-overridable, keeping request framing consistent with the recorded URL/body/media-type inputs.

Header names are retained in the request descriptor.

The full target URL is retained in the request descriptor. Operators should therefore keep credentials out of URLs and query strings and use runtime headers instead.

The adapter does not claim observation of:

~~~text
provider-internal model execution
remote infrastructure
hidden prompts
hidden model state
chain-of-thought
actual hardware execution
~~~

## Local process adapter

`ProcessAdapter` executes an argv vector directly with:

~~~text
shell = false
~~~

It records:

~~~text
argv descriptor
stdin
stdout
stderr
exit status as declared adapter metadata
~~~

The inherited environment is deliberately not retained.

Do not place credentials in argv if they should not become evidence.

The adapter does not claim observation of:

~~~text
child-internal control flow
kernel scheduling
library internals
hidden external side effects
~~~

## Failure reporting

Transport failures, HTTP error statuses, timeouts, launch failures, non-zero exits, truncated responses, and configured capture-limit failures produce an `AdapterObservation` whose completion event has:

~~~text
collection_status = COLLECTION_FAILED
~~~

The raised adapter exception carries that observation so the caller can still persist and independently verify the failure evidence.

Failure evidence is not silently discarded because the operation itself failed.

## Persistence

`persist_observation()` composes the existing modules:

~~~text
AdapterObservation
    ↓
LocalEvidenceStore
    ↓
LocalCustodyLedger
    ↓
finalize()
    ↓
independent verification
~~~

It does not define a new store or verifier.

The same persistence path accepts observations from both reference adapters.

## Exit-gate demonstration

Phase 10 tests execute two structurally different systems:

~~~text
local HTTP server
local child process
~~~

Both emit evidence through the same provider-neutral contract and the existing core schema.

The test then persists both observations into one store and verifies the resulting bundle and custody chain without provider-specific changes to `provenance-core`.

## CI

~~~bash
python3 -m unittest discover -s tests -p 'test_generic_adapters.py' -v
~~~

GitHub Actions runs the same lane in `.github/workflows/adapters.yml`.
