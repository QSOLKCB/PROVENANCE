# PROVENANCE Custody — v1

## Status

~~~text
CUSTODY_SCHEMA=provenance.custody.v1
CUSTODY_LEDGER_FORMAT=provenance.local-custody.v1
CLOCK_ORDERING_AUTHORITY=PREVIOUS_CUSTODY
WALL_CLOCK_ORDERING_AUTHORITY=NO
~~~

Phase 4 adds a minimal append-only chain of custody without changing the meaning of Phase 1 artifacts/events or the Phase 2 bundle contract.

Custody answers:

~~~text
what evidence identity is being handled
what custody action was recorded
when that custody observation was recorded
which actor/source was observed or declared, if known
which custody record immediately preceded it
~~~

It does not assign liability, legal identity, physical possession, or intent.

---

# Custody actions

The initial vocabulary is:

~~~text
CAPTURED
STORED
VERIFIED
EXPORTED
TRANSFERRED
SUPERSEDED
~~~

SUPERSEDED requires a related_identity identifying the replacement or successor evidence.

The other actions may also include a related identity when separately supported by evidence.

---

# Canonical custody core

A custody core binds:

~~~text
subject_identity
action
recorded_at
clock_source
clock_assurance
actor
source
previous_custody
related_identity
~~~

Structured custody identity uses:

~~~text
PROVENANCE/CUSTODY/v1
~~~

and canonical JSON under the repository canonicalization contract.

The envelope stores:

~~~text
core
custody_identity
self_hash_exclusion = custody_identity
~~~

---

# Unknown actor/source

Unknown values remain explicit nulls.

Correct:

~~~text
actor = null
source = null
~~~

Incorrect:

~~~text
actor = guessed-user
source = assumed-system
~~~

Custody history must not manufacture a handler merely to make the chain appear complete.

---

# Chain ordering

Authoritative chain order is cryptographic:

~~~text
previous_custody
~~~

not chronological sorting by wall-clock time.

For one subject identity:

~~~text
ROOT
  ↓ previous_custody
NEXT
  ↓
NEXT
  ↓
TIP
~~~

The independent verifier rejects:

- forks;
- dangling predecessors;
- links across subjects;
- duplicate custody identities;
- disconnected chains;
- tampered record identities.

Clock timestamps are evidence about observed time.

They are not the chain-order authority.

---

# Time observation

PROVENANCE does not implement an NTP server or time daemon.

It observes existing host time tooling.

Preferred local sequence:

~~~text
chronyc sources
chronyc tracking
chronyc authdata
~~~

When chrony has a selected network source:

~~~text
clock_source = chrony:<selected-source>
~~~

If the selected source reports NTS authentication:

~~~text
clock_assurance = AUTHENTICATED_NETWORK
~~~

If chrony has a selected unauthenticated network source:

~~~text
clock_assurance = NETWORK
~~~

A local reference clock remains:

~~~text
clock_assurance = LOCAL
~~~

When chrony is unavailable, ordinary custody recording falls back directly to the host system clock.

PROVENANCE does not automatically initiate a network time query.

An operator may explicitly request the diagnostic helper:

~~~text
ntpdate -q pool.ntp.org
~~~

or another explicitly supplied server token.

That query is observation-only and opt-in.

PROVENANCE does not start a time service and does not open UDP/TCP time listeners.

Automatic chrony inspection uses numeric output mode for sources, tracking, and authentication data so clock observation does not trigger hostname-resolution traffic.

If the explicit diagnostic helper is used, its decimal offset text is parsed into integer nanoseconds without binary floating-point arithmetic. The host clock is read as integer nanoseconds, offset arithmetic is integer-only, and base-60/RFC3339 conversion occurs only at the presentation boundary.

The recorded diagnostic timestamp may retain:

~~~text
clock_source = ntpdate:<server>;offset=<observed-offset>
clock_assurance = NETWORK
~~~

If no network time observation is available:

~~~text
clock_source = system-clock
clock_assurance = LOCAL
~~~

Future signed timestamp authorities may use:

~~~text
clock_assurance = SIGNED_ATTESTATION
~~~

but are outside the Phase 4 implementation.

---

# Clock assurance is not truth scoring

Clock assurance states what evidence supported the timestamp source.

It does not prove:

- physical location;
- human identity;
- event truth;
- legal time;
- perfect synchronization;
- absence of network delay.

Authenticated network time raises time-source assurance.

It does not upgrade unrelated custody claims.

---

# Local custody ledger

The Phase 4 reference ledger combines two lock layers:

~~~text
same-process mutex keyed by custody-root filesystem identity
+
POSIX fcntl advisory record lock
~~~

The process-local layer serializes threads and multiple ledger instances inside one process. It also prevents PROVENANCE from opening/closing the custody lock file through another instance while a process-owned POSIX lock is held.

The POSIX layer serializes cooperating writers across processes.

The Phase 4 reference ledger uses:

~~~text
custody/
├── CUSTODY_FORMAT
├── .custody.lock
├── staging/
└── records/
    └── sha256/
        └── <custody-digest>.json
~~~

Only records/sha256 is authoritative custody history.

staging/ is non-authoritative publication workspace.

The ledger deliberately has no authoritative mutable per-subject HEAD file.

Current tips are derived from immutable custody records by independent verification.

Appending follows:

~~~text
acquire same-process mutex
→ acquire POSIX record lock
→ recover stale staging files
→ verify current ledger
→ derive current subject tip
→ construct next custody record
→ write+fsync staging file
→ atomically link immutable record into records/sha256
→ fsync authoritative records directory
→ remove staging name
→ fsync staging directory
→ independently verify complete ledger
→ release POSIX lock
→ release same-process mutex
~~~

No successful append may create a fork.

A crash before final-name publication may leave only a staging file; reopen removes it under the writer lock.

A crash after final-name publication may leave both the authoritative record and a staging name; reopen preserves the verified record and removes the stale staging name under the writer lock.

Unexpected files inside records/sha256 remain verification failures and are never silently cleaned up.

---

# Relationship to the Phase 3 store

The Phase 3 evidence store and Phase 4 custody ledger are separate modules.

This avoids silently changing the already-published Phase 3 store layout.

Conceptually:

~~~text
evidence store
    │
    └── artifact/event/manifest identities

custody ledger
    │
    └── custody records referring to those identities
~~~

A custody record may refer to:

- artifact content identity;
- artifact-record identity;
- event identity;
- manifest identity;
- later evidence identities as contracts expand.

Phase 11 portable bundles may package both store evidence and custody records.

Phase 4 does not force that bundle-version change early.

---

# Local HTTP/UI security boundary

The future read-only HTTP viewer is not part of Phase 4, but custody data is sensitive enough that the network boundary is fixed now:

~~~text
default bind = 127.0.0.1
public/LAN bind = explicit operator action
UI authority = NONE
~~~

The viewer should use:

~~~text
small local HTTP server
pure HTML
pure CSS
minimal vanilla JavaScript
~~~

No inetd-style miscellaneous network services are required.

The viewer must not define or mutate evidence semantics.

---

# Failure semantics

A failed custody append must not silently become successful history.

An invalid existing ledger blocks new append operations.

Verification failures remain verification failures.

Clock observation failure does not break custody recording if a lower-assurance local system timestamp is recorded instead.

The default observation path must not create network traffic merely to obtain time.

---

# Core rule

~~~text
CHAIN ORDER COMES FROM CRYPTOGRAPHIC LINKS.
TIME SOURCE ASSURANCE IS EXPLICIT.
UNKNOWN HANDLERS REMAIN UNKNOWN.
CUSTODY RECORDS ARE APPEND-ONLY.
~~~
