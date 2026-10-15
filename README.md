# AI Security Architect — labs as notebooks

The Udemy *AI Security Architect (Sovereign Defense)* course spends its first module
building a bare-metal sandbox (Proxmox, Kubernetes, Terraform, a FastAPI wrapper,
Ollama) and then attacks it. The attacks themselves are HTTP calls to a local model.
This repo skips the infrastructure and runs each attack as a notebook against a model
already served on `127.0.0.1:11434` (Ollama).

## Layout

    labkit.py                   the model + the "look for X in the output" check
    module02_injection.ipynb    Labs 11-20  — prompt injection & jailbreaking
    labs-source.md              the extracted course text, all 100 labs
    (more modules added as built)

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

Most labs are pure prompting and run as-is. Two are not:
- **Lab 18 (GCG adversarial suffix)** needs raw weights + `transformers` (gradients),
  not a served model. Marked `raw` in the notebook; point it at a local HF model.
- **Module 9 (hardware-rooted security — TPM, SEV-SNP, attestation)** genuinely needs
  the metal and can't be reproduced in a notebook. Those labs are read, not run.
