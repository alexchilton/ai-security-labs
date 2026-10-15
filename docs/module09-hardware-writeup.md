# Module 9 — Hardware-Rooted Security & Sovereign Deployment  ·  write-up (read-only)

OWASP maps loosely here (supply-chain / infrastructure hardening around the model). This module
moves from software-defined controls to a **hardware root of trust**: the guarantees come from a
TPM, a confidential-computing CPU/GPU, an HSM, or the network fabric — not from code the model runs.

**Why this module is a write-up, not notebooks.** Every lab depends on hardware or cluster
infrastructure a laptop cannot reproduce, and — unlike the RAG or agent labs — there is no honest
software substitute. A notebook that "simulates" a TEE or a TPM quote teaches the *wrong* lesson: the
entire point of these controls is that the guarantee is enforced below the software layer, where a
compromised OS or root user cannot forge it. So each lab is documented: the threat, the control, what
it requires, and where you could actually run it.

Everything below is for an **authorised, self-owned deployment**.

---

### Lab 81 — Shielding model weights with TEEs
**Threat:** model weights (the IP) sit in cleartext host RAM during inference; a privileged attacker
or a compromised hypervisor reads them out.
**Control:** run inference inside a Trusted Execution Environment (Intel SGX / AMD SEV-SNP) — an
encrypted "secure room" in the processor whose memory even root cannot read.
**Requires:** an SGX or SEV-SNP capable CPU, an enclave runtime (Gramine, Occlum, or a SEV-SNP guest).
**Where to run:** a confidential-computing VM (Azure DCsv3/DCasv5, GCP Confidential VMs, AWS Nitro
Enclaves). No laptop substitute.

### Lab 82 — NVIDIA Blackwell Confidential Computing
**Threat:** the GPU is outside the CPU TEE — weights and activations are in cleartext VRAM even when
the CPU side is protected.
**Control:** GPU confidential computing — encrypted VRAM and an attested GPU, so the data is protected
on the accelerator too.
**Requires:** a Hopper (H100 CC) or Blackwell GPU in CC mode + the NVIDIA attestation stack.
**Where to run:** a cloud CC-GPU instance. Not the RTX 3080 (no CC mode).

### Lab 83 — Secure Boot + verifiable attestation for GPU nodes
**Threat:** a node joins the cluster already compromised (tampered firmware, rootkit) and you cannot
tell.
**Control:** measured boot into a TPM, which produces a signed **quote**; a remote attestation service
verifies the measurements before the node is trusted with weights or data.
**Requires:** TPM 2.0, UEFI Secure Boot, an attestation service (e.g. Keylime). `tpm2-tools` can
produce a quote on real hardware.
**Where to run:** a physical node with a TPM. A quote can be demoed on such a box; the full
measured-boot→quote→verify chain is a node exercise.

### Lab 84 — Encrypting LLM weights in memory and at rest
**Threat:** weights stolen from disk or a memory dump.
**Control:** envelope encryption — weights encrypted at rest with a data key, the data key wrapped by a
key that lives in Vault/HSM and is only released to an attested process (ties back to 83).
**Requires:** HashiCorp Vault (transit engine) or a KMS, plus attestation for key release.
**Partial software analogue (not built):** `cryptography` Fernet/AES-GCM to encrypt a weights blob at
rest is a fair *at-rest* demo — but the hard part (releasing the key only to an attested, TEE-resident
process) is exactly the hardware part, so a notebook would show the easy half and miss the point.

### Lab 85 — Air-gapped high-availability AI cluster
**Threat:** any network path is an exfiltration path; a sovereign deployment must run with no internet
egress yet stay highly available.
**Control:** an air-gapped K8s cluster with internal-only registries, mirrored dependencies, and HA
across nodes with no outbound route.
**Requires:** a multi-node Kubernetes cluster, an internal registry (Harbor), offline mirroring.
**Where to run:** real cluster infrastructure.

### Lab 86 — Zero-Trust Network Access (ZTNA) for AI interfaces
**Threat:** a VPN is moat-and-castle — once inside, a user roams freely to every model and tool.
**Control:** ZTNA — per-request identity and authorization, so a user reaches only the specific
endpoint they are entitled to, never the whole network.
**Requires:** a ZTNA broker (Cloudflare Access, Teleport, or an identity-aware proxy) + an IdP.
**Where to run:** real infrastructure. (The application-layer analogue — per-tool RBAC — is Module 7
Lab 61.)

### Lab 87 — HSM integration for AI key management (root of trust)
**Threat:** the keys that encrypt weights and sign attestations are themselves stolen from software.
**Control:** keys are generated in and never leave a Hardware Security Module; the application sends
data *to* the HSM to be signed/decrypted, so a host compromise cannot steal the key.
**Requires:** an HSM (CloudHSM, Luna, YubiHSM) or Vault's PKCS#11 integration.
**Where to run:** real HSM or a cloud KMS. The *pattern* (sign/verify without holding the private key)
is shown in Module 7 Lab 65's cryptographic HITL — but there the "HSM" is a Python key object, which
is the thing an HSM exists to replace.

### Lab 88 — Multi-region failover for sovereign AI
**Threat:** a single site is a single point of failure; sovereignty must survive a region loss without
leaking data across borders.
**Control:** a globally resilient mesh with data-residency-aware failover — replicas per region,
failover that respects which data may cross which boundary.
**Requires:** multi-region K8s, a global load balancer, replicated encrypted storage.
**Where to run:** real multi-region infrastructure.

### Lab 89 — Traffic inspection for encrypted AI payloads
**Threat:** attacks and exfiltration hide inside mTLS tunnels; you cannot inspect what you cannot
decrypt.
**Control:** terminate/re-originate TLS at an inspection proxy (or use eBPF-based visibility) to scan
prompt/response payloads for injection and data exfiltration without breaking transport security.
**Requires:** a service mesh (Istio/Envoy) or an inspection gateway, plus the Module 3 content filters
applied at the proxy.
**Where to run:** real mesh infrastructure. The *content* inspection logic is Modules 3 & 5; this lab
is about where in the fabric it runs.

### Lab 90 — Milestone: fully sovereign, hardware-secured deployment
**The grand synthesis:** compose 81–89 — attested CC nodes (81–83), envelope-encrypted weights (84),
air-gapped HA (85), ZTNA (86), HSM root of trust (87), multi-region failover (88), payload inspection
(89) — into one deployment where trust is rooted in hardware end to end.
**Requires:** all of the above. Read-only; this is an architecture to understand, and to build on real
infrastructure if and when it exists.

---

### How this module relates to the runnable ones

The application-layer analogues of several hardware controls are already built and executed:
cryptographic sign/verify (Module 7 Lab 65 ≈ HSM pattern of Lab 87), per-tool least privilege
(Module 7 Lab 61 ≈ ZTNA of Lab 86), content inspection (Modules 3 & 5 ≈ the payload scanning of Lab
89). Module 9's lesson is that at the highest assurance level those guarantees are moved *below* the
software — into silicon and fabric — where a software compromise cannot defeat them. The notebooks
show the logic; this module names where the logic has to live to be trustworthy under a stronger
threat model.
