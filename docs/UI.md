# PROVENANCE Phase 9 — Read-Only UI

Phase 9 adds a deliberately small human inspection surface without changing evidence semantics.

~~~text
MODULE=provenance-ui
AUTHORITY=READ_ONLY_PRESENTATION
DEFAULT_BIND=127.0.0.1
FRONTEND=PURE_HTML_CSS_MINIMAL_VANILLA_JS
WRITES_TO_EVIDENCE=FORBIDDEN
~~~

## Run

From the repository root:

~~~bash
python3 -m provenance_ui \
  --store /path/to/provenance-store \
  --custody /path/to/provenance-custody
~~~

The default address is:

~~~text
http://127.0.0.1:8765/
~~~

LAN or public binding requires explicit operator action:

~~~bash
python3 -m provenance_ui \
  --store /path/to/provenance-store \
  --custody /path/to/provenance-custody \
  --host 0.0.0.0 \
  --allow-non-loopback
~~~

No authentication is added in Phase 9. Non-loopback exposure is therefore an explicit operator choice, not a default deployment mode.

## Read-only boundary

The viewer consumes only finalized store snapshots and immutable custody records.

It does not call:

~~~text
LocalEvidenceStore.finalize()
LocalEvidenceStore.put_artifact()
LocalEvidenceStore.put_event()
LocalCustodyLedger.append()
~~~

It also avoids constructing the mutable store/ledger reference objects merely to display data, because their initialization and recovery paths may legitimately modify operational state.

Instead it:

1. reads the store HEAD,
2. locates the corresponding immutable snapshot,
3. runs `verify_bundle()`,
4. reads canonical event and artifact metadata from that snapshot,
5. reads immutable custody records,
6. runs `verify_custody_records()`,
7. builds a presentation-only projection.

The HTTP surface accepts only:

~~~text
GET
HEAD
~~~

Mutation methods return HTTP 405.

## Views

The first viewer contains:

- evidence graph,
- custody timeline,
- artifact inspector,
- event inspector,
- independent verification dimensions,
- evidence-gap panel.

Graph actor/tool/human groupings are explicitly presentation-derived labels. They do not create evidence or change cryptographic identity.

## Time and ordering

Event schema v1 contains no event timestamp.

The viewer therefore does **not** copy custody timestamps onto events.

It presents:

~~~text
timestamped custody records
+
untimed events
+
relationship-derived partial ordering
~~~

Custody chain order remains governed by `previous_custody`, not wall-clock sorting.

## Verification dimensions

The viewer never collapses independent claims into a generic `TRUSTED` badge.

It reports separate dimensions such as:

~~~text
integrity = VERIFIED | FAILED | NOT_PRESENT
custody   = VERIFIED | PARTIAL | INVALID | NOT_PRESENT
signature = NOT_PRESENT
replay    = NOT_ATTEMPTED
~~~

`custody = PARTIAL` means the custody ledger verifies cryptographically but does not contain a custody subject for every finalized artifact/event/manifest identity.

Phase 9's live store/custody viewer does not accept detached Phase 12 package-signature or external-anchor sidecars. Its `signature = NOT_PRESENT` value therefore means **no signature is present in the viewer input model**, not that no detached signature exists elsewhere. Phase 12 authenticity is verified with `verify-assurance`; see [TRUST.md](TRUST.md).

## Evidence gaps

The initial viewer surfaces, at minimum:

- open manifest scope,
- manifest-declared missing artifacts,
- non-RECORDED collection status,
- event timestamps unavailable under event schema v1,
- partial custody coverage,
- integrity verification failure,
- custody verification failure.

A displayed gap is presentation of existing evidence state. It is not itself a new evidence record.

## Non-authority invariant

Phase 9 must satisfy:

~~~text
delete provenance-ui
→ same evidence bytes
→ same identities
→ same verifier outcomes
~~~

The UI test fingerprints the evidence roots before and after direct projection and HTTP requests to detect accidental mutation.

## CI

~~~bash
python3 -m unittest discover -s tests -p 'test_ui.py' -v
~~~

GitHub Actions runs the same Phase 9 lane in `.github/workflows/ui.yml`.
