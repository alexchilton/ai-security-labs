# Do the OWASP LLM mitigations actually work? — expected vs actual, all 10 classes

Every OWASP LLM section recommends mitigations. This repo *measured* them against real attacks on a
local model, instead of taking the efficacy on faith. Below, each class: the course's expected result,
what was measured, whether they agree, and the executed notebook that proves it.

**Model:** one aligned 7B (`qwen2.5:7b`) at default temperature, unless noted. The transferable result
is the **ranking of control types**, not the exact percentages — a stronger model shifts the baseline.
Course claims are paraphrased from the public OWASP taxonomy and the course; no course text is reproduced.

**The one sentence that summarises all of it:** *trust structure, not the model.* Deterministic,
model-independent controls hold; behavioural (prompt-level) controls are unreliable and can backfire;
detection controls are only as good as their model and threshold.

---

## LLM01 — Prompt Injection  ·  `efficacy_llm01_defences.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| keyword denylist | "trivially bypassed" | blocks 5/11, misses every obfuscated attack | ✅ |
| **prompt hardening** | "raises the bar" | **81.8% leak vs 45.5% baseline — WORSE** | ❌ backfires |
| **data/instruction separation** | "highest-leverage defence" | **72.7% leak — also worse than baseline** | ❌ backfires |
| semantic filter | works, generic embedders underperform | blocks 11/11 but **33% false positives** | ~ mixed |
| output filtering | "critical last line" | **0% leak, deterministic** | ✅ |
| LLM judge (small) | "not foolproof, use fine-tuned" | 3B judge ineffective (= baseline) | ✅ caveat confirmed |

**Headline:** two recommended controls (hardening, delimiters) made leakage *worse* on this model —
naming the attack vectors in the system prompt appears to prime them. The deterministic output filter
is the only single control that fully holds.

## LLM02 — Sensitive Information Disclosure  ·  `module08_inversion_privacy.ipynb`, `gap_llm09`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| PII redaction before model | removes PII | spaCy NER + ordered regex redact name/email/phone/card/IBAN | ✅ |
| output scanning for secrets | catches egress leaks | deterministic scrub removes the verbatim secret (0 leaks) | ✅ |
| keep secrets out of the prompt | architectural | confirmed: a secret in the system prompt leaks under injection (LLM01) | ✅ |

Deterministic redaction works; the caveat (shared with LLM01's output filter) is it catches the
*verbatim* secret — a model coaxed into transforming it (base64, spelling) slips past, so pair with
semantic detection.

## LLM03 — Supply Chain  ·  `gap_llm03_supply_chain.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| artifact hash verification | blocks tampered models | tampered blob rejected on hash mismatch | ✅ |
| safe deserialisation | pickle runs code on load | poisoned pickle executes; restricted unpickler blocks it | ✅ |
| dependency pinning | prevents confusion | unpinned/internal names flagged | ✅ |
| typosquat detection | catches near-names | edit-distance flags numpyy/pandaa/requsts | ✅ |

All structural, all hold. The course is correct throughout — these are classic supply-chain controls.

## LLM04 — Data & Model Poisoning  ·  `module05_securing_rag.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| **document signing** | provenance stops poisoning | signed-only retrieval drops poison before the model sees it; capstone retrieves 0 poison | ✅ strong |
| anomaly detection | flags poisoned embeddings | IsolationForest on 1024-dim needs ~1000 vectors; on 40 it catches obvious poison, misses in-distribution | ~ weak secondary |
| boundary framing / grounding | treats retrieved as data | **obeyed on the 7B** — framing alone did not hold | ❌ weak |

**Headline (matches LLM01):** the structural control (signing) is load-bearing; the prompt-level
controls (framing, grounding) were obeyed by the model. Anomaly detection is a weak secondary net.

## LLM05 — Improper Output Handling  ·  `efficacy_llm05_output.ipynb`, `gap_llm05`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| context-specific encoding | neutralises XSS | `html.escape` makes the `<img>` inert | ✅ |
| SQL parameterisation | "the only safe path" | string-built injects, parameterised does not | ✅ |
| shell argv / escaping | prevents cmd injection | `shell=True` runs the payload, argv does not | ✅ |
| schema value constraints | catches invalid values | enum rejects `admin`, range rejects negative | ✅ |
| "model intent is not a control" | safe-SQL prompt ≠ safe SQL | AST gate blocks a real DROP regardless of the prompt | ✅ |

Every claim holds — because output handling is structural (classic AppSec), not behavioural.

## LLM06 — Excessive Agency  ·  `module07_zero_trust.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| least-privilege / path validation | denies out-of-scope | traversal `../../etc/passwd` denied deterministically | ✅ |
| tool contract (Pydantic) | rejects bad args | malformed account id / over-limit amount rejected | ✅ |
| **cryptographic HITL** | human can't be forged | agent can't produce the Ed25519 signature; self-approval and replay both fail | ✅ strong |
| semantic tool-call monitoring | blocks dangerous intent | blocks `/etc/shadow` read + credential-exfil, passes benign (threshold-tuned) | ✅ |
| depth/time limits | bounds runaway loops | loop halts at the step cap; injected `max_steps=-1` rejected | ✅ |

The capstone: the Module 6 tool-hijack is deterministically refused by the gate. Structural agent
controls hold; the earlier (Module 6) prompt-level "follow instructions safely" did not.

## LLM07 — System Prompt Leakage  ·  `module02_injection.ipynb`, `module04_rag_poisoning.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| **don't embed secrets in the prompt** | the only real fix | confirmed: a key in the system prompt leaks under reconstruction / base64 attacks | ✅ |
| instruction hardening | raises the bar | weak — same backfire risk as LLM01 | ~ weak |
| output filtering for prompt content | catches egress | deterministic scrub of the secret works | ✅ |

The course's own framing ("treat the system prompt as adversary-readable") is the right one: the
architectural fix (no secrets in the prompt) is the only reliable control; hardening is not.

## LLM08 — Vector & Embedding Weaknesses  ·  `module05_securing_rag.ipynb`

Same controls and results as LLM04 (they share the RAG stack): **signing** is the strong control
(unsigned poison never retrieved), RBAC/clearance scoping works, anomaly detection is a weak
secondary, and prompt-level framing of retrieved content does not hold alone. ✅ signing / ❌ framing.

## LLM09 — Misinformation  ·  `gap_llm09_misinformation.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| grounding (answer only from sources) | stops fabrication | unanswerable query returns "not supported" instead of inventing | ✅ |
| cosine groundedness | detects drift | **accepts a same-topic contradiction (0.69)** — topicality ≠ entailment | ❌ insufficient alone |
| LLM-as-judge entailment | catches unsupported | correctly blocks the fabricated claim | ✅ |
| confidence from retrieval | flags thin coverage | low top-match flagged as "may not be covered" | ✅ |

Grounding works; cosine alone is necessary-not-sufficient (it passed a contradiction), which is why
the entailment judge is needed — a measured nuance the "just add grounding" framing misses.

## LLM10 — Unbounded Consumption  ·  `module03_guardrails.ipynb`, `module06_agentic.ipynb`

| mitigation | course expects | measured | agree? |
|---|---|---|---|
| sliding-window token quota | caps denial-of-wallet | blocks after the budget is spent | ✅ |
| agent step/time limits | bounds runaway loops | loop halts at the cap (also LLM06) | ✅ |

Structural resource controls hold deterministically.

---

## The pattern across all 10 classes

| control type | efficacy | examples |
|---|---|---|
| **structural / deterministic** | **holds** | signing, parameterisation, output encoding, hash verification, crypto HITL, quotas, path validation, schema enums |
| **detection (model/stat)** | holds *if* tuned/capable | semantic filter (FP cost), entailment judge (needs a capable model), anomaly detection (needs data) |
| **behavioural / prompt-level** | **unreliable, can backfire** | prompt hardening, delimiter data-separation, grounding-by-instruction, "generate safe X" intent |

The three OWASP sections that recommend prompt-level controls as primary (LLM01 hardening, LLM04/08
retrieved-content framing, LLM07 instruction hardening) are exactly where the measurement **contradicts**
the expected efficacy on this model. Everywhere the controls are structural, the course's claims hold.

**Bottom line, measured not asserted:** the OWASP mitigations are real, but their efficacy ranges from
*negative* to *perfect*. Build defence-in-depth with the deterministic, model-independent controls
carrying the load; treat every prompt-level control as a weak layer that may even backfire; and never
let a mitigation's presence in a checklist substitute for measuring that it works on your model.
