# README4AIs.md

```text
PROJECT=PROVENANCE
REPOSITORY=QSOLKCB/PROVENANCE
PURPOSE=FRAMEWORK_AGNOSTIC_CRYPTOGRAPHIC_CHAIN_OF_CUSTODY
STATUS=BOOTSTRAP_SPECIFICATION
PRIMARY_CONSTITUTION=AGENTS.md
HUMAN_OVERVIEW=README.md
LICENSE=MPL-2.0
```

# MACHINE ENTRYPOINT

This file is intended primarily for AI agents, coding agents, automated reviewers, and machine-assisted development systems.

Before modifying this repository:

```text
READ AGENTS.md
READ README.md
READ relevant implementation/specification files
INSPECT current repository state
THEN reason about changes
```

Priority:

```text
AGENTS.md
    >
explicit repository contracts/specifications
    >
tests/fixtures
    >
README4AIs.md
    >
README.md explanatory material
    >
agent assumptions
```

If an assumption conflicts with repository evidence:

```text
REPOSITORY_WINS
```

If uncertainty remains:

```text
DO_NOT_INVENT
REPORT_UNCERTAINTY
```

---

# PROJECT MISSION

PROVENANCE records verifiable evidence describing:

```text
WHO
WHAT
WHEN
WHERE
WHY
HOW
```

for actions performed by:

```text
AI systems
LLMs
agents
software
tools
services
humans
automated workflows
distributed systems
```

Primary objective:

```text
CAPTURE
IDENTIFY
BIND
PRESERVE
VERIFY
PRESENT
```

PROVENANCE is:

```text
OBSERVER
RECORDER
EVIDENCE SYSTEM
CHAIN-OF-CUSTODY SYSTEM
VERIFICATION SYSTEM
```

PROVENANCE is NOT:

```text
CONTROLLER
POLICY ENGINE
GUARDRAIL
TRUTH ORACLE
JUDGE
LIABILITY ENGINE
MODEL ALIGNMENT SYSTEM
AUTOMATIC INTERPRETER
```

---

# PRIMARY INVARIANT

```text
MONITORED_SYSTEM_BEHAVIOUR
        |
        v
OBSERVATION
        |
        v
EVIDENCE
```

MUST NOT become:

```text
MONITORED_SYSTEM_BEHAVIOUR
        |
        v
OBSERVATION
        |
        v
MODIFICATION
        |
        v
DIFFERENT_SYSTEM_BEHAVIOUR
```

Rule:

```text
MONITORING != CONTROL
```

---

# NON-INTERFERENCE

PROVENANCE MUST NOT silently modify:

```text
prompts
responses
tool inputs
tool outputs
model parameters
execution order
application state
decisions
external actions
retry behaviour
failure behaviour
success behaviour
```

Observation overhead may exist.

Observation overhead MUST NOT be represented as nonexistent if materially relevant.

Collectors MUST report failure rather than modify monitored behaviour to preserve apparent continuity.

---

# EVIDENCE CLASSES

Minimum classes:

```text
OBSERVED
DECLARED
DERIVED
```

## OBSERVED

Directly captured by an observation mechanism.

Examples:

```text
request bytes
response bytes
tool invocation
tool result
file bytes
process status
API response
runtime event
```

Meaning:

```text
PROVENANCE_OBSERVED_VALUE
```

NOT necessarily:

```text
VALUE_IS_TRUE
```

---

## DECLARED

Asserted by an external actor/system.

Examples:

```text
reported model identifier
reported user identifier
provider metadata
operator-entered case ID
declared runtime version
model-supplied rationale
```

Rule:

```text
DECLARED != INDEPENDENTLY_VERIFIED
```

Never silently promote DECLARED to OBSERVED or VERIFIED.

---

## DERIVED

Calculated from retained evidence.

Examples:

```text
hash
Merkle root
elapsed duration
timeline
verification result
dependency relation
replay comparison
report
```

Requirement:

```text
DERIVED -> SOURCE_EVIDENCE_REFERENCE_REQUIRED
```

---

# RAW EVIDENCE

Original evidence MUST remain distinguishable from derivatives.

```text
RAW
 |
 +-> canonical representation
 +-> normalized derivative
 +-> index
 +-> timeline
 +-> report
 +-> visualization
 +-> analysis
```

Forbidden:

```text
overwrite raw evidence
repair raw evidence in place
normalize
