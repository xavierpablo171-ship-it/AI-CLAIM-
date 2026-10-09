# ==============================================================================
# AI-CLAIM — Celda 22/22
# IP: Apache 2.0 puro + licencia comercial scoped + inventario separado
# ==============================================================================
import pathlib

IP_DIR = pathlib.Path("ai_claim_real_pkg")
LEGAL_INTERNAL = IP_DIR / "legal_internal"
LEGAL_PUBLIC = IP_DIR / "legal_public"
LEGAL_INTERNAL.mkdir(exist_ok=True)
LEGAL_PUBLIC.mkdir(exist_ok=True)

APACHE_LICENSE = """                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

Copyright 2026 Pablo Javier Lazarte

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

NOTICE: The Apache 2.0 license above applies to the AI-CLAIM Community
Edition (files in `src/ai_claim_real/`). It does NOT apply to any
Enterprise Edition or proprietary modules distributed separately.
"""
(IP_DIR / "LICENSE").write_text(APACHE_LICENSE)


COMMERCIAL_LICENSE = """# AI-CLAIM — Commercial License (Template)

**Version 1.0.0 — 2026**

## 1. Scope

This commercial license applies **only** to the AI-CLAIM Enterprise
Edition, distributed separately from the Apache-2.0 Community Edition:

- `ai_claim_enterprise/hsm_integrations/`
- `ai_claim_enterprise/private_adapters/`
- `ai_claim_enterprise/enterprise_controls/`
- `ai_claim_enterprise/deployment_tools/`
- `ai_claim_enterprise/sla_support/`

This license does **not** apply to any file distributed under Apache 2.0.

## 2. Grant

Subject to payment of applicable fees, AI-CLAIM grants a non-exclusive,
non-transferable, non-sublicensable right to use, modify, and deploy the
Enterprise Edition internally for the Licensee's business purposes.

## 3. Restrictions

The Licensee shall not redistribute, sublicense, lease, or rent the
Enterprise Edition; remove proprietary notices; or use it to develop a
competing product.

## 4. License Tiers

| Tier | Eligibility | Annual Fee (USD) |
|------|-------------|------------------|
| Evaluation | 90-day non-production trial | 0 |
| Startup | < US$5M ARR | 25,000 |
| Enterprise | > US$5M ARR | Custom |
| OEM | Embedding in a commercial product | Custom |

## 5. Intellectual Property

All IP rights in the Enterprise Edition remain the exclusive property
of Pablo Javier Lazarte.

## 6. Governing Law

Pending: this template names Singapore as a placeholder because AI-CLAIM's
initial institutional targets are there (MAS, IMDA) — but no legal entity
has been formed yet in any jurisdiction (see roadmap). Do not sign a real
agreement under this clause until an actual entity exists and counsel has
confirmed the governing law makes sense for that entity and the counterparty.

## 7. Contact

**Pablo Javier Lazarte** — Independent Researcher & Systems Architect
"""
(IP_DIR / "COMMERCIAL_LICENSE.md").write_text(COMMERCIAL_LICENSE)


NDA = """# Mutual Non-Disclosure Agreement

Entered into as of [DATE] between Pablo Javier Lazarte ("Discloser") and
[RECIPIENT NAME] ("Recipient").

## 1. Confidential Information
Non-public information disclosed by Discloser, including source code,
algorithms and architecture of the Enterprise Edition, private adapters,
HSM integrations, benchmarks not published, and business/pricing terms.

## 2. Obligations
Recipient will hold Confidential Information in strict confidence, not
disclose it to third parties without written consent, use it solely for
evaluation, and return or destroy it on request.

## 3. Exclusions
Publicly available information, information known prior to disclosure,
independently developed information, and information required to be
disclosed by law.

## 4. Term
5 years from the date of disclosure.

## 5. Governing Law
See note in COMMERCIAL_LICENSE.md — placeholder pending entity formation.

**Discloser:** Pablo Javier Lazarte    Signature: _______  Date: _____
**Recipient:** [NAME]                  Signature: _______  Date: _____
"""
(LEGAL_INTERNAL / "NDA_TEMPLATE.md").write_text(NDA)


IP_PUBLIC = """# AI-CLAIM — Public IP Disclosure (DRAFT — not yet published)

**Author:** Pablo Javier Lazarte, Independent Researcher & Systems Architect

**Status:** DRAFT. This file does not yet constitute a legal defensive
publication — that requires actually submitting it to an external,
timestamped, public venue (e.g., arXiv cs.CR, IP.com) per the project
roadmap. Until then this is a private working draft.

## Overview

AI-CLAIM is a cryptographic attestation layer that separates AI
evaluation logic from cryptographic attestation, binding a frozen
evaluation protocol to the resulting evidence via a signed, hash-chained
log.

## Design Elements

### Two-Engine Separation
- **Motor A (Evaluation):** executes a frozen protocol, produces a
  deterministic result. Fails closed on invalid input.
- **Motor B (Attestation):** verifies protocol and result before signing,
  chains the result in an append-only, signature-verified audit log.

The protocol is hashed (SHA3-512, domain-separated) before execution,
together with a hash of the evaluator code and dataset — not just the
rules — so a post-hoc change to any of these is detectable.

### Post-Quantum Signatures
ML-DSA-65 (NIST FIPS 204) via liboqs. Cross-verification with OpenSSL
requires OpenSSL 3.5+ with native ML-DSA support; on older OpenSSL this
step is unavailable, not silently assumed to pass.

### Regulatory Mapping (honest scope)
AI-CLAIM's audit log provides SUPPORTING evidence — never a claim of
DIRECT satisfaction — for a small, named subset of the 230 official
control objectives in the FS AI RMF v1.0 (U.S. Treasury / Cyber Risk
Institute, published 2026). The underlying frameworks (FS AI RMF, NIST
AI RMF, EU AI Act, MAS SAFR) are the work of their respective bodies;
AI-CLAIM's own contribution is the code and mapping methodology, not
the frameworks themselves.

## Defensive Publication Status

Intended as prior art once actually published externally with a
third-party timestamp. The SHA3-512 hash of the final, externally-hosted
version is the operative timestamp — not the hash of this local draft.
"""
(LEGAL_PUBLIC / "IP_INVENTORY_PUBLIC.md").write_text(IP_PUBLIC)


IP_INTERNAL = """# AI-CLAIM — Internal IP Inventory (CONFIDENTIAL, do not publish)

**Author:** Pablo Javier Lazarte

## 1. Pre-existing IP (author-owned)
- Two-engine architecture concept (Motor A / Motor B)
- Frozen protocol methodology (binds evaluator+dataset+seed, not just rules)
- Regulatory mapping METHODOLOGY and code
- Initial code, tests, and documentation

## 2. Grant-funded public IP (if applicable)
- [To be determined based on grant terms]

## 3. Proprietary commercial IP (not published)
- HSM vendor-specific integrations
- Private adapters (blockchain, storage)
- Enterprise deployment tools, commercial SLA/support infrastructure

## 4. Third-party frameworks referenced (NOT author's IP — cite, don't claim)
- FS AI RMF v1.0 — U.S. Treasury / Cyber Risk Institute
- NIST AI RMF 1.0 — NIST AI 100-1
- EU AI Act (Art. 12) — European Union
- MAS SAFR — Monetary Authority of Singapore

## 5. Third-party components (licensed)
- liboqs (MIT), python-pkcs11 (MIT), fastapi (MIT), pydantic (MIT)

## 6. Open-source components (Community Edition)
- Apache 2.0 licensed core, public API and verifier

## 7. Trademark
- Mark: AI-CLAIM — status: to be filed (IPOS Singapore + USPTO)

## 8. Patent considerations
- Candidate claims under review by qualified counsel
- No provisional application filed as of this writing

## 9. Legal review status
- Pending professional IP review before any public disclosure
- NDA required before sharing this inventory
- Governing-law clauses in COMMERCIAL_LICENSE.md/NDA are placeholders
  pending formation of an actual legal entity
"""
(LEGAL_INTERNAL / "IP_INVENTORY_INTERNAL.md").write_text(IP_INTERNAL)


structure_doc = """# AI-CLAIM — Repository Structure
