# AI Security Architect — labs as notebooks

The Udemy *AI Security Architect (Sovereign Defense)* course spends its first module
building a bare-metal sandbox (Proxmox, Kubernetes, Terraform, a FastAPI wrapper,
Ollama) and then attacks it. The attacks themselves are HTTP calls to a local model.
This repo skips the infrastructure and runs each attack as a notebook against a model
already served on `127.0.0.1:11434` (Ollama).

## Layout

    labkit.py                      the model, the RAG store, the "look for X in the output" check
    module02_injection.ipynb          Labs 11-20  — prompt injection & jailbreaking (LLM01)
    module03_guardrails.ipynb         Labs 21-30  — input/output guardrails (LLM01 defences)
    module04_rag_poisoning.ipynb      Labs 31-40  — RAG poisoning & exfiltration (LLM04/08)
    module05_securing_rag.ipynb       Labs 41-50  — securing the vector store (LLM08 defences)
    module06_agentic.ipynb            Labs 51-60  — agentic exploitation & MCP (LLM06)
    module07_zero_trust.ipynb         Labs 61-70  — zero-trust orchestration (LLM06 defences)
    module08_inversion_privacy.ipynb  Labs 71-80  — inversion, extraction, privacy (LLM02/10)
    module10_redteam_capstone.ipynb   Labs 91-100 — red teaming, compliance, capstone (full OWASP)
    docs/module09-hardware-writeup.md Labs 81-90  — hardware-rooted security (read-only write-up)
    docs/not-runnable-labs.md         write-ups for labs that need infra/hardware/GPU
    gap_llm05_output_handling.ipynb   LLM05 — output handling: XSS/SQLi/SSTI/cmd/path (course gap)
    gap_llm03_supply_chain.ipynb      LLM03 — supply chain: integrity/pickle/pinning/typosquat/BOM
    gap_llm09_misinformation.ipynb    LLM09 — misinformation: hallucination, grounding, verification
    efficacy_llm01_defences.ipynb     LLM01 — do injection defences work (hardening backfires)
    efficacy_llm02_sensitive_info.ipynb  LLM02 — PII redaction + output secret-scanning
    efficacy_llm03_supply_chain.ipynb    LLM03 — hash-verify / safe-unpickle / typosquat
    efficacy_llm04_poisoning.ipynb       LLM04 — signing vs framing vs anomaly on a RAG poison
    efficacy_llm05_output.ipynb       LLM05 — encoding / parameterisation / schema
    efficacy_llm06_agency.ipynb          LLM06 — path / contract / crypto-HITL / step-cap
    efficacy_llm07_system_prompt.ipynb   LLM07 — no-secret-in-prompt vs hardening vs scrub
    efficacy_llm08_vector.ipynb          LLM08 — clearance-scoped retrieval, signed provenance
    efficacy_llm09_misinformation.ipynb  LLM09 — grounding / cosine / entailment judge
    efficacy_llm10_consumption.ipynb     LLM10 — token quota / step cap / deadline
    docs/mitigation-efficacy-summary.md  one-page expected-vs-actual across all 10 classes
    labs-source.md                    extracted course text (gitignored — paid content)

## OWASP Top 10 for LLM (2025) anchoring

Each module maps to the industry-standard OWASP risk IDs, so the project reads against the
framework rather than the course's arbitrary numbering:

| module | OWASP risk |
|---|---|
| 2 Prompt Injection | **LLM01** Prompt Injection |
| 3 Guardrails | **LLM01** defences |
| 4 RAG Poisoning & Exfiltration | **LLM04** Data/Model Poisoning, **LLM08** Vector/Embedding |
| gap_llm05 output handling | **LLM05** Improper Output Handling ✓ |
| gap_llm03 supply chain | **LLM03** Supply Chain ✓ |
| gap_llm09 misinformation | **LLM09** Misinformation ✓ |

The *gap* rows are classes the Udemy course under-covers; built as extra modules on the same
harness, same executed-clean bar.

## Does each mitigation actually work? — per-section efficacy (all 10)

Every OWASP section recommends a mitigation. Each `efficacy_llmNN_*.ipynb` *measures* its section's
mitigation against a real attack on the local model and prints an expected-vs-actual table — the
numbers come from the executed run, they are not asserted. `docs/mitigation-efficacy-summary.md`
collects all ten onto one page. The pattern that falls out:

| control type | efficacy | examples |
|---|---|---|
| structural / deterministic | **holds** | signing, parameterisation, encoding, hash-verify, crypto HITL, quotas, path/schema checks |
| detection (model/stat) | holds *if* tuned/capable | semantic filter (FP cost), entailment judge, anomaly detection (needs data) |
| behavioural / prompt-level | **unreliable, can backfire** | prompt hardening (LLM01), retrieved-content framing (LLM04/08), instruction hardening (LLM07) |

The sections whose primary control is prompt-level (LLM01, LLM04/08, LLM07) are exactly where the
measurement contradicts the expected efficacy on this 7B. Measured, not assumed — a stronger model
may narrow the gap, so the transferable result is the ranking of control types, not the percentages.

Each lab stands in for a real incident. `docs/real-world-exploits.md` links every OWASP class to the
public attacks and research it reproduces — the Bing "Sydney" leak, the Chevrolet $1 Tahoe, EchoLeak
(CVE-2025-32711), PoisonGPT, Air Canada's hallucinating chatbot, and others — mapped to the notebook
that measures the matching defence.

## Run

    ollama serve                       # if not already running
    ollama pull qwen2.5:7b             # default target (aligned, fast)
    jupyter lab module02_injection.ipynb

`labkit.py` has no dependencies beyond the standard library (pandas optional, only for
the verdict tables). A few individual labs want extras, each flagged in its cell:
`tiktoken` (Lab 13 visual), `deep-translator` (Lab 16), `torch`+`transformers` (Lab 18),
`garak` (Lab 20).

## Models

| role | model | why |
|---|---|---|
| default target | `qwen2.5:7b` | alignment-trained so it refuses; fast enough for a 10-attack sweep |
| strong target | `qwen3.8:27b-q4_K_M` | resists the cruder jailbreaks — see which attacks survive |
| ceiling | `Qwen3-14B-abliterated` | no safety training — shows what full compliance looks like |

MLX builds are flagged and avoided: they break structured output (so any JSON-parsing
guardrail lab must use a GGUF build).

## What is and isn't portable

Most labs are pure prompting or local HTTP and run as-is. The exceptions are marked `raw`
in their notebooks:
- **Lab 18 (GCG adversarial suffix)** needs raw weights + `transformers` (gradients),
  not a served model. Point it at a local HF model.
- **Lab 40 (DNS C2 exfiltration)** needs `scapy` + root/raw sockets; the HTTP callback
  variant in the same notebook shows the identical two-stage exfil without root.
- The vector-store labs use an in-process `labkit.VectorStore` on `bge-m3` instead of the
  course's Milvus/Chroma + Docker — same embed-and-retrieve attack surface, no infra.
- **Module 9 (hardware-rooted security — TPM, SEV-SNP, attestation)** genuinely needs
  the metal and can't be reproduced in a notebook. Those labs are read, not run.
