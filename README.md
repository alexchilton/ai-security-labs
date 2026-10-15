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
    docs/not-runnable-labs.md         write-ups for labs that need infra/hardware/GPU
    labs-source.md                    extracted course text (gitignored — paid content)
    (modules 9-10 + gap modules in progress)

## OWASP Top 10 for LLM (2025) anchoring

Each module maps to the industry-standard OWASP risk IDs, so the project reads against the
framework rather than the course's arbitrary numbering:

| module | OWASP risk |
|---|---|
| 2 Prompt Injection | **LLM01** Prompt Injection |
| 3 Guardrails | **LLM01** defences |
| 4 RAG Poisoning & Exfiltration | **LLM04** Data/Model Poisoning, **LLM08** Vector/Embedding |
| *gap* output handling | **LLM05** Improper Output Handling |
| *gap* supply chain | **LLM03** Supply Chain |
| *gap* misinformation | **LLM09** Misinformation |

The *gap* rows are classes the Udemy course under-covers; built as extra modules on the same
harness, same executed-clean bar.

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
