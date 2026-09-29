# PROVENANCE Phase 15 — Distributed Custody

Phase 15 supports evidence crossing independently operated systems without manufacturing a global custody chain or total clock order.

The reference mechanism is an **offline signed handoff** of a finalized Phase 11 forensic package.

~~~text
sender system
    ↓
verified Phase 11 package
    ↓
signed transfer offer
    ↓
finalized transfer bundle
    ↓
offline / removable / delayed transport
    ↓
receiver verification
    ↓
receiver-local custody acknowledgements
    ↓
signed transfer receipt
~~~

No network service is required.

## Core ordering rule

Distributed transfer is explicitly:

~~~text
ordering = PARTIAL
~~~

Sender and receiver clocks are verified independently.

PROVENANCE does **not** infer:

~~~text
sender_time < receiver_time
therefore
sender caused receiver
~~~

The protocol instead records direct causal evidence:

~~~text
package identity
    ↓ offered_for_transfer
signed offer identity
    ↓ acknowledged_by_receiver
signed receipt identity
~~~

Each local custody ledger keeps its own predecessor chain.

## Sender transfer bundle

Layout:

~~~text
transfer/
├── transfer.json
├── offer.json
├── offer.signature.json
└── package/
    └── <unchanged Phase 11 forensic package>
~~~

The embedded Phase 11 package remains the authority for sender-side evidence identity and the sender custody snapshot already archived inside that package.

Phase 15 does not create a second competing sender-custody representation.

`transfer.json` binds every transfer member by path, SHA-256 content identity, and byte count.

Its domain-separated identity is:

~~~text
PROVENANCE/TRANSFER-BUNDLE/v1
~~~

## Signed sender offer

The offer binds:

~~~text
package identity
evidence manifest identity
source system label
destination system label
sender-local offered_at clock observation
~~~

The offer is signed with:

~~~text
OpenSSH SSHSIG
algorithm = ssh-ed25519
namespace = provenance-transfer
role = sender
subject kind = transfer_offer
~~~

The transfer bundle binds the exact signature-record identity.

### Signature claim boundary

A verified sender signature proves that the offer bytes were signed by the private key corresponding to the embedded Ed25519 public key.

It does **not** by itself prove:

~~~text
legal identity
organization ownership of the key
DNS/domain ownership
employment
authorization policy
trusted timestamp
public publication
~~~

Mapping a signing key to a real organization remains separate evidence.

## Offline and partition-tolerant handoff

The bundle is a self-contained directory.

It can be:

~~~text
copied to removable media
held while the receiver is offline
transferred through an out-of-band channel
queued during a network partition
copied between isolated hosts
~~~

and verified later.

The reference protocol performs no automatic network requests.

This is partition tolerance by **store-and-forward evidence**, not by distributed consensus.

## Receiver acceptance

The receiver first verifies:

~~~text
transfer envelope and closure
sender offer identity
sender signature
embedded Phase 11 package
intended destination system
package identity
source package custody/integrity
~~~

Only then does receiver-local state change.

The received package preserves exactly the sender package identity.

The receiver appends local custody for that package identity in this order:

~~~text
CAPTURED
    ↓
STORED
    ↓
VERIFIED
~~~

Each acknowledgement binds:

~~~text
actor = receiver system label
source = sender system label
related_identity = sender offer identity
receiver-local clock observation
~~~

This remains one local linear custody chain.

It is not spliced into the sender's local chain.

## Crash recovery

Receiver acceptance is resumable.

If a process stops after recording only a valid prefix such as:

~~~text
CAPTURED
~~~

or:

~~~text
CAPTURED
STORED
~~~

a later retry may append only the missing suffix.

The existing acknowledgements must be exactly a prefix of:

~~~text
CAPTURED
STORED
VERIFIED
~~~

and must use one consistent receiver clock observation.

Arbitrary reordered subsets are rejected.

## Signed receiver receipt

Receipt layout:

~~~text
receipt/
├── receipt.json
├── receipt.signature.json
└── receiver_custody/
    └── sha256/
        └── <custody-record>.json
~~~

The receipt binds:

~~~text
transfer bundle identity
offer identity
package identity
source system
destination system
receiver-local accepted_at clock
receiver custody-record identities
ordering = PARTIAL
~~~

It is signed under the same SSHSIG namespace with:

~~~text
role = receiver
subject kind = transfer_receipt
~~~

The receipt verifier independently checks the receiver custody chain and requires the offer-specific acknowledgements to appear exactly as:

~~~text
CAPTURED → STORED → VERIFIED
~~~

## Duplicate delivery

Repeated delivery of the same transfer to the same already-completed receipt is idempotent.

The receiver:

1. verifies the existing signed receipt;
2. verifies the transfer bundle and received package bindings;
3. verifies that the live receiver custody ledger still contains the custody identities bound by the receipt;
4. returns the same receipt identity;
5. appends **no new custody records**.

If the live custody ledger has disappeared or no longer contains those acknowledgements, duplicate delivery fails rather than silently pretending continuity.

## Independent verification

Verify the sender handoff:

~~~bash
provenance verify-transfer \
  --transfer /path/to/transfer
~~~

Verify a receipt alone:

~~~bash
provenance verify-receipt \
  --receipt /path/to/receipt
~~~

Verify the complete handoff:

~~~bash
provenance verify-receipt \
  --receipt /path/to/receipt \
  --transfer /path/to/transfer \
  --package /path/to/received-package
~~~

The report keeps dimensions separate:

~~~text
receiver receipt integrity
receiver signature
receiver local custody
transfer-bundle binding
received-package binding
ordering = PARTIAL
~~~

## CLI workflow

Create a transfer:

~~~bash
provenance transfer-create \
  --package /path/to/source-package \
  --source-system org-a/system-1 \
  --destination-system org-b/system-9 \
  --sender-key /path/to/sender-ed25519-key \
  --output /path/to/transfer
~~~

Accept it:

~~~bash
provenance transfer-receive \
  --transfer /path/to/transfer \
  --package-destination /receiver/evidence/package \
  --receipt /receiver/evidence/receipt \
  --custody /receiver/custody \
  --receiver-system org-b/system-9 \
  --receiver-key /path/to/receiver-ed25519-key \
  --expected-sender-fingerprint 'SHA256:<trusted-sender-fingerprint>'
~~~

The sender fingerprint must come from an independent trust channel, not from the transfer bundle being accepted. Acceptance fails closed when the supplied fingerprint does not match the signing key.

The package, transfer bundle, and receipt are distinct immutable identities.

## Filesystem publication

Transfer, received-package, and receipt publication reuse the repository's kernel-enforced no-replace publication rule.

Existing destinations are never intentionally overwritten.

Transfer destinations must remain outside immutable source packages/bundles.

## Remote artifact identity

The transferred subject is the Phase 11 package identity.

A successful receiver binding requires:

~~~text
sender package identity
==
transfer subject identity
==
received package identity
==
receipt subject identity
~~~

No remote filename, path, host label, or transport identifier replaces cryptographic identity.

## Partial custody and uncertainty

Phase 15 does not claim that distributed custody is globally complete.

The source package may itself contain explicit custody gaps.

The receiver receipt proves only its declared local acknowledgements.

Unknown transport handlers, missing external custody, or unobserved intervals remain unknown.

The protocol does not fill those gaps with synthetic actors.

## What Phase 15 does not provide

The reference implementation is not:

~~~text
a message broker
a consensus protocol
a replicated database
a global sequence service
a trusted timestamp network
a PKI mapping keys to organizations
a proof that an offline courier handled evidence correctly
a guarantee of exactly-once physical delivery
~~~

It provides verifiable **at-least-once handoff evidence with idempotent receiver acceptance** for the same completed receipt.

## CI exit-gate evidence

The Phase 15 suite executes:

~~~text
real Ed25519 sender signature
real Ed25519 receiver signature
offline copied transfer bundle
sender/receiver wall clocks intentionally reversed
package identity preservation
receiver custody CAPTURED/STORED/VERIFIED
signed receipt verification
duplicate delivery without duplicate custody
duplicate delivery after live custody loss → fail
partial receiver custody prefix → deterministic resume
wrong receiver → reject before local mutation
tampered sender offer → reject before local mutation
tampered receipt → verification failure
~~~

~~~bash
python3 -m unittest tests.test_transfer -v
~~~
