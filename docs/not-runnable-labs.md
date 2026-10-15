# Labs that can't run as notebooks — write-ups

Most of the course runs as notebooks against local Ollama. A minority need infrastructure,
raw sockets, root, GPU weights, or physical hardware. Rather than skip them, each is written
up here: what the lab does, why it can't be a notebook cell, and what the real implementation
requires. Grouped by the reason it's non-runnable.

Everything here is described for a **local, authorised, single-host lab** — no real targets.

---

## Infrastructure (Docker / Kubernetes / external services)

### Lab 31 — Deploy Milvus (standalone)
Spins up Milvus via docker-compose (three containers: etcd, MinIO, Milvus engine).
**Why not a notebook:** needs Docker + a running multi-container service on ports 19530/9091.
**Substitute used:** `labkit.VectorStore` — in-process embed-and-retrieve on `bge-m3`. Same
attack surface (nearest-by-cosine retrieval the pipeline trusts); no infra.
**Real version:** `docker-compose up -d` with the official compose file, then `pymilvus`
`connections.connect(host, 19530)`. Needed only if you want to test Milvus-specific controls
(RBAC, TLS, TDE below).

### Lab 41 — Milvus RBAC
Object-level roles: a `Junior_Dev` role granted ReadOnly on `public_docs`, barred from
`payroll_vectors`.
**Why not a notebook:** requires Milvus auth (`common.authCheck.enabled: true`) and the
`pymilvus` `Role`/`User` APIs against a live server.
**Substitute used (Module 5):** clearance-scoped retrieval — a `clearance` field per doc,
retrieval filtered by the caller's level. Shows the *logic*; Milvus enforces it in production.
**Real version:** connect as `root`, `Role("Junior_Dev").create()`, `role.grant("Collection",
"public_docs", "ReadOnly")`. The control that matters: the model for a guest user is never even
*shown* the restricted collection.

### Lab 48 — Vector data encryption (TLS + at-rest)
Self-signed CA, server cert, `tlsMode: 2` for transit, TDE for disk.
**Why not a notebook:** openssl cert generation + Milvus TLS config + disk-encryption at the
storage layer — all server/host configuration.
**Substitute used (Module 5):** summarised. The application-layer analogue is Fernet-encrypting
vector blobs before they hit disk, but transit TLS and TDE are infrastructure concerns.
**Real version:** `openssl genrsa`/`req`/`x509` to build the CA and server cert, mount into
Milvus, set `tlsMode: 2` and storage encryption in `milvus.yaml`.

---

## Sandboxing / kernel isolation

### Lab 43 — Sandboxed document parsers (gVisor)
Parse untrusted PDFs/Docs inside gVisor (`runsc`) so a malicious document that triggers a parser
exploit can't reach the host kernel.
**Why not a notebook:** gVisor is a user-space kernel installed as a Docker runtime
(`/etc/docker/daemon.json`), needs root to install and a container runtime to use.
**Substitute used (Module 5):** summarised as a concept.
**Real version:** install `runsc`, register it as a Docker runtime, build a parser image
(`unstructured[pdf]` + poppler + tesseract), run parsing jobs with `--runtime=runsc`. The
principle: never parse attacker-supplied files in the same trust domain as the orchestrator.
A lighter local stand-in worth building: parse in a `subprocess` with `resource` limits + a
`seccomp` filter, or in a short-lived container — not kernel-isolation, but process isolation.

---

## Raw sockets / root

### Lab 40 — DNS-based C2 exfiltration (scapy)
A fake DNS server sniffs UDP/53 for `<base64-secret>.exfil.ai-lab.com` lookups the model is
tricked into resolving.
**Why not a notebook:** `scapy` packet sniffing needs root and raw sockets; binding/sniffing
:53 conflicts with the host resolver.
**Substitute used (Module 4):** the HTTP callback variant — same two-stage exfil (model embeds a
URL carrying the secret; a renderer fetches it) caught by `labkit.Listener`, no root.
**Real version:** `sniff(filter="udp port 53", prn=...)` under sudo, decoding the subdomain label
as base64. The lesson (smuggle a secret out via an outbound lookup the model is coaxed into) is
identical to the HTTP version.

---

## GPU weights / gradients

### Lab 18 — GCG adversarial suffix
Gradient-optimise a suffix string that forces an affirmative start ("Sure, here is…").
**Why not a notebook (as an Ollama call):** GCG needs the raw model weights and backprop
(`transformers` + `torch`), not a served inference endpoint — Ollama exposes no gradients.
**Substitute used (Module 2):** the mechanism is explained and a single optimisation step shown
in a `raw` cell; the hand-crafted suffix is used in later labs.
**Real version:** load a local HF model (`AutoModelForCausalLM`, fp16, a non-gated checkpoint like
`Qwen2.5-7B-Instruct`), run the greedy-coordinate-gradient loop (500+ iters) against a target
string. Runs on the box; it is a different setup from the rest of the course, not a different
notebook.

---

## Physical hardware / firmware (Module 9 — read-only)

Module 9 (Hardware-Rooted Security & Sovereign Deployment) is **read, not run** in full. These
depend on a TPM, a confidential-computing CPU/GPU, or secure-boot firmware that a notebook on a
Mac cannot reproduce or fake.

### Lab 81 — Shielding model weights with TEEs
Run inference inside a Trusted Execution Environment so weights are never in cleartext host RAM.
**Requires:** Intel SGX / AMD SEV-SNP / an enclave runtime. No software substitute is honest —
a notebook "simulating" an enclave teaches nothing real.

### Lab 82 — NVIDIA Blackwell Confidential Computing
GPU-side confidential compute (encrypted VRAM, attested GPU).
**Requires:** a Blackwell (or Hopper CC) GPU with CC mode and the NVIDIA attestation stack.

### Lab 83 — Secure Boot + verifiable attestation for GPU nodes
Measured boot, TPM quote, remote attestation of the node before it joins the cluster.
**Requires:** a TPM 2.0, UEFI secure boot, an attestation service. `tpm2-tools` can demo a
*quote* on hardware with a TPM, but the chain (measured boot → quote → remote verify) is a
physical-node exercise.

### Lab 90 — Milestone: fully sovereign hardware-secured deployment
Composition of 81–83 on real hardware. Read-only.

**What to do instead:** read these for the threat model and the control names (attestation,
sealed storage, measured boot, encrypted VRAM). If you ever have a TPM-equipped box or a CC-capable
GPU, Labs 81/83 become runnable there — not on this laptop.

---

## Summary table

| Lab | reason | substitute | runnable where |
|---|---|---|---|
| 31 Milvus | Docker service | `VectorStore` (in-proc) | a box with Docker |
| 41 RBAC | Milvus auth | clearance-scoped retrieval | Milvus server |
| 48 TLS/TDE | host/storage config | summarised | Milvus server |
| 43 gVisor | kernel runtime + root | summarised; subprocess stand-in possible | Linux host + root |
| 40 DNS C2 | raw sockets + root | HTTP callback (`Listener`) | Linux host + sudo |
| 18 GCG | gradients/weights | single-step `raw` cell | the RTX 3080 box |
| 81–83, 90 | TPM / CC hardware | read-only | hardware with TPM/SEV |
