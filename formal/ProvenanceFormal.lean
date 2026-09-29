/-
PROVENANCE Phase 18 formal model.

Frozen implementation target:
  tag    v1.0.0
  commit 0b1a2eea6c3c2b40a7f2a390fcd3410c75fab742

This file proves properties of the model below. The correspondence between
this model and the frozen runtime implementation is documented separately in
docs/FORMAL_VERIFICATION.md. These theorems do not claim whole-program
verification of the Python/Rust implementation.
-/

namespace ProvenanceFormal

abbrev Identity := String

inductive EvidenceClass where
  | observed
  | declared
  | derived
  deriving DecidableEq, Repr

structure EventCore where
  evidenceClass : EvidenceClass
  actor : String
  operation : String
  inputs : List Identity
  outputs : List Identity
  deriving DecidableEq, Repr

structure Envelope (α : Type) where
  core : α
  storedIdentity : Identity
  deriving Repr

/-- Recompute an envelope identity only from its core. -/
def recomputeIdentity {α : Type}
    (identityFn : α → Identity) (envelope : Envelope α) : Identity :=
  identityFn envelope.core

/-- Seal a core by computing its identity independently of the envelope field. -/
def sealEnvelope {α : Type}
    (identityFn : α → Identity) (core : α) : Envelope α :=
  { core := core, storedIdentity := identityFn core }

/--
FV-01 / INV-HSH-2:
the stored self-identity field is outside the identity input.
-/
theorem selfHashExclusion {α : Type}
    (identityFn : α → Identity) (core : α) :
    recomputeIdentity identityFn (sealEnvelope identityFn core) =
      identityFn core := by
  rfl

/--
FV-01 / INV-HSH-2:
changing only the stored envelope identity cannot change recomputation.
-/
theorem storedIdentityDoesNotAffectRecomputation {α : Type}
    (identityFn : α → Identity) (core : α) (left right : Identity) :
    recomputeIdentity identityFn
        { core := core, storedIdentity := left } =
      recomputeIdentity identityFn
        { core := core, storedIdentity := right } := by
  rfl

/-- Append a new custody/history record without rewriting prior records. -/
def appendRecord {α : Type} (history : List α) (record : α) : List α :=
  history ++ [record]

/-- A small explicit prefix relation used by the append-only model. -/
def IsHistoryPrefix {α : Type} (prior whole : List α) : Prop :=
  ∃ suffix, whole = prior ++ suffix

/--
FV-02 / INV-CUS-1 / INV-EVD-3:
appending a record preserves the complete prior history as a prefix.
-/
theorem appendOnlyPrefix {α : Type} (history : List α) (record : α) :
    IsHistoryPrefix history (appendRecord history record) := by
  exact ⟨[record], rfl⟩

/--
FV-02 / INV-CUS-1 / INV-EVD-3:
a previously present history record remains present after append.
-/
theorem priorRecordSurvivesAppend {α : Type}
    {item record : α} {history : List α}
    (h : item ∈ history) :
    item ∈ appendRecord history record := by
  simp [appendRecord, h]

/--
Model the CLI/MCP rule that caller-supplied assertions enter as DECLARED.
-/
def recordCallerDeclaration (actor operation : String) : EventCore :=
  {
    evidenceClass := .declared
    actor := actor
    operation := operation
    inputs := []
    outputs := []
  }

/--
FV-03 / INV-CLS-3:
a caller declaration is represented as DECLARED.
-/
theorem callerDeclarationRemainsDeclared (actor operation : String) :
    (recordCallerDeclaration actor operation).evidenceClass =
      EvidenceClass.declared := by
  rfl

/--
FV-03 / INV-CLS-3:
the declaration path cannot silently produce OBSERVED evidence.
-/
theorem callerDeclarationIsNotObserved (actor operation : String) :
    (recordCallerDeclaration actor operation).evidenceClass ≠
      EvidenceClass.observed := by
  intro h
  cases h

/-- A transformation that changes presentation/operation text only. -/
def changeOperation (event : EventCore) (operation : String) : EventCore :=
  { event with operation := operation }

/--
FV-03 / INV-CLS-3 / INV-CLS-5:
changing a non-classification field preserves the evidence class.
-/
theorem operationChangePreservesClassification
    (event : EventCore) (operation : String) :
    (changeOperation event operation).evidenceClass =
      event.evidenceClass := by
  rfl

structure EvidenceState where
  artifactIds : List Identity
  eventIds : List Identity
  custodyIds : List Identity
  deriving DecidableEq, Repr

/--
A read-only presentation returns its source unchanged alongside the rendered
view. The renderer receives the source but has no mutation operation.
-/
def projectReadOnly {β : Type}
    (render : EvidenceState → β) (source : EvidenceState) :
    EvidenceState × β :=
  (source, render source)

/--
FV-04 / INV-EVD-5 / INV-ARC-3:
presentation preserves the source evidence state.
-/
theorem presentationPreservesSource {β : Type}
    (render : EvidenceState → β) (source : EvidenceState) :
    (projectReadOnly render source).1 = source := by
  rfl

end ProvenanceFormal
