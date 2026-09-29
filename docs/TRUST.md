# PROVENANCE Phase 12 — Signatures and External Anchoring

Phase 12 adds **optional authenticity mechanisms** without changing the Phase 1 evidence core or the Phase 11 package identity.

Trust records are detached sidecars.

~~~text
forensic-package/
  package.json
  ...

package.signature.json
package.git-anchor.json
~~~

The package remains independently verifiable without either sidecar.

## Assurance dimensions

Phase 12 keeps assurance multidimensional:

~~~text
integrity        = VERIFIED | FAILED
signature        = VERIFIED | FAILED | NOT_PRESENT | UNAVAILABLE
external_anchor  = VERIFIED | FAILED | NOT_PRESENT | NOT_ATTEMPTED | UNAVAILABLE
~~~

A valid historical state can therefore be:

~~~text
integrity        = FAILED
signature        = VERIFIED
external_anchor  = VERIFIED
~~~

This means the current package no longer matches its declared members, while the signature and external anchor still verify the exact package declaration that was signed/anchored.

It does **not** mean the damaged package is valid.

## Signature mechanism

The Phase 12 reference signature mechanism is:

~~~text
OpenSSH SSHSIG
algorithm = ssh-ed25519
namespace = provenance
signed bytes = exact canonical package.json bytes
~~~

The detached canonical signature record stores:

~~~text
subject package identity
SHA-256 identity of signed package.json bytes
algorithm
SSHSIG namespace
normalized ssh-ed25519 public key
derived SHA256 key fingerprint
ASCII-armored SSH signature
~~~

The signature record has its own domain-separated identity:

~~~text
PROVENANCE/SIGNATURE-RECORD/v1
~~~

### What a verified signature proves

A successful verification establishes that:

~~~text
the exact package.json bytes presented to the verifier
were signed under the provenance SSHSIG namespace
using the private key corresponding to
the embedded ssh-ed25519 public key
~~~

It does **not** by itself prove:

~~~text
human identity
organization identity
legal authority
truth of the signed statements
intent
physical location
trusted time
~~~

Key ownership and real-world identity require separate evidence.

## Signing

Generate or select an Ed25519 SSH key.

For an automation/test key:

~~~bash
ssh-keygen -t ed25519 -f ./provenance-signing-key
~~~

Create a detached signature record:

~~~bash
provenance sign-package \
  --package /path/to/forensic-package \
  --key ./provenance-signing-key \
  --output ./package.signature.json
~~~

The producer independently verifies the Phase 11 package before signing and then signs the exact canonical `package.json` bytes.

The package directory is not modified.

The reference implementation also accepts an `ssh-ed25519` public-key file when the matching private key is available through an OpenSSH agent.

## Git commit anchoring

The first external anchor mechanism is an existing Git commit.

The anchor payload is canonical PROVENANCE JSON binding:

~~~text
schema
canonicalization
subject_kind = forensic_package
subject_identity = <package identity>
~~~

### 1. Write the exact payload

~~~bash
provenance anchor-payload \
  --package /path/to/forensic-package \
  --output /path/to/anchor-repo/anchors/package.provenance
~~~

### 2. Commit it

~~~bash
git -C /path/to/anchor-repo add anchors/package.provenance
git -C /path/to/anchor-repo commit -m "Anchor PROVENANCE package"
~~~

### 3. Create the detached anchor record

~~~bash
provenance anchor-git \
  --package /path/to/forensic-package \
  --git-repo /path/to/anchor-repo \
  --commit HEAD \
  --path anchors/package.provenance \
  --output ./package.git-anchor.json
~~~

The command does **not** create or push the Git commit.

It only verifies that the supplied commit already contains the exact canonical anchor payload and records that binding.

The record binds:

~~~text
package identity
Git object format
exact commit OID
repository-relative path
anchor payload SHA-256
optional repository hint
~~~

The anchor record has domain-separated identity:

~~~text
PROVENANCE/EXTERNAL-ANCHOR/v1
~~~

## What Git-anchor verification proves

Given a supplied Git object database, successful verification establishes:

~~~text
the referenced commit object exists
and
the referenced path in that commit
contains the exact canonical payload
for the package identity
~~~

It does **not** prove:

~~~text
the commit was pushed to GitHub
the commit was publicly visible
the commit author is a real-world identity
the commit timestamp is trusted time
the repository was append-only forever
~~~

Those claims require additional external evidence.

The verifier reads the committed object, not the working tree. Later working-tree modifications do not rewrite the historical anchor.

## Multidimensional verification

~~~bash
provenance verify-assurance \
  --package /path/to/forensic-package \
  --signature ./package.signature.json \
  --anchor ./package.git-anchor.json \
  --git-repo /path/to/anchor-repo
~~~

Result dimensions remain separate:

~~~json
{
  "integrity": "VERIFIED",
  "signature": "VERIFIED",
  "external_anchor": "VERIFIED"
}
~~~

If no signature or anchor is supplied, the relevant dimension is `NOT_PRESENT`.

If an anchor record is supplied without a Git repository, the anchor record itself can be parsed but external verification is `NOT_ATTEMPTED`.

If `ssh-keygen` or `git` is unavailable, the affected optional mechanism reports `UNAVAILABLE`; core package integrity verification remains independent.

## Python APIs

Signing and anchor record production are intentionally separated from verification:

~~~python
from provenance_trust.records import (
    create_signature_record,
    create_git_anchor_record,
    write_trust_record,
)

from provenance_verify import verify_assurance
~~~

The verifier does not need the private signing key.

## MCP boundary

Phase 12 does not add private-key signing to MCP.

Reasons:

~~~text
private keys must not become ordinary MCP arguments
credentials/key material must not become evidence payloads
signing authority is an operator-side capability
MCP remains optional to verification
~~~

Detached trust records may be verified independently outside MCP.

## Network and blockchain boundary

Phase 12 performs no automatic network calls.

Git anchoring verifies local Git objects only.

Future mechanisms may include signed releases, transparency logs, timestamp authorities, DOI records, external append-only services, and blockchain anchors.

They remain optional replaceable mechanisms behind the same assurance boundary.

Blockchain is not required.

## CI

The Phase 12 trust lane executes real Ed25519 SSH key generation, real SSHSIG signing and verification, real Git commit anchoring, working-tree mutation after commit, detached-record tamper detection, and assurance-dimension separation.

~~~bash
python3 -m unittest tests.test_trust -v
~~~
