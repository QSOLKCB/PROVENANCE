# Manually derived exact-byte expectation

This local analytic derivation is a declaration, not a machine-certified proof
of independence. The expected fixture was written directly; it was not captured
from the producer, copied from its output, or regenerated during verification.

For input {"z": [null, true, false, 42], "a": "café\n"}, apply the intended
provenance.canonical-json.v1 rules: sort the two object keys so `a` precedes `z`;
keep array order; use lowercase JSON null/booleans and decimal integer 42; omit
separator spaces; keep é as UTF-8 bytes c3 a9; encode the string's newline as
backslash followed by n; terminate the entire JSON document with one LF.

The resulting literal is retained in expected.json. Its 41 bytes are:
7b2261223a22636166c3a95c6e222c227a223a5b6e756c6c2c747275652c66616c73652c34325d7d0a

The subject source is provenance_core/canonical.py in QSOLKCB/PROVENANCE at
41451bf690597a75f461299dfcbbee559c83e924. That file is bound independently as a
source artifact. This fixture is a later local check of that source contract,
not evidence of an upstream historical run. One matching vector does not prove
general canonicalization correctness, execution authenticity, or independence.
