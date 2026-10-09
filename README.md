# # AI-CLAIM

**A cryptographic attestation layer for AI evaluation.**

AI-CLAIM binds an evaluation protocol to its result with a signed,
hash-chained audit record, so that any third party can verify what was
evaluated, under which rules, and whether anything was altered afterwards —
without trusting the party that ran the evaluation.

Version: 0.1.0 (alpha)
License: Apache 2.0
Status: Not FIPS 140-3 certified. Not externally audited. See "Limits".

---

## The problem

When an AI system is evaluated today, the output is a document. It says
"this passed." It does not prove that the evaluation protocol was not
adjusted after the results were seen, that the evaluator was the one
authorized to run it, or that the result was not modified in transit.

Regulators are beginning to demand verifiable evidence, not PDFs. The
Banco Central do Brasil stated in September 2026 that banks accept AI
results "without mechanisms to verify metadata." The FSB's July 2026
consultation identified the same gap.

AI-CLAIM addresses that specific gap.

## What this is

- A **frozen protocol**: rules, evaluator hash, dataset hash, and seed
  are committed to before evaluation begins, bound by a single SHA3-512
  hash, recorded in an append-only audit chain.
- **Two engines**, separated:
  - **Motor A** executes the frozen protocol. Holds no signing key.
  - **Motor B** verifies protocol and result before signing. Refuses
    to sign if either verification fails.
- An **append-only audit chain** with ML-DSA-65 signatures. Verifies
  hash, signature, and index in a single pass. Accepts an optional
  external anchor (`expected_head`).
- A **third-party verifier** that does not import the pipeline.
- A **portable bundle** (`verify_bundle_standalone.py`) with a status
  and an `error_code`.

## What this is not

- **Not a governance platform.** It sits *below* Credo AI, Holistic
  AI, OneTrust, and makes their output verifiable.
- **Not an auditor.** It does not perform bias testing or red-teaming.
- **Not certified.** No FIPS 140-3. No SOC 2. No ISO 27001.
- **Not a claim of compliance.** The regulatory mapping is *SUPPORTING
  evidence* for a small, named subset of the FS AI RMF v1.0 control
  objectives. It is never *DIRECT* satisfaction.

## Architecture

Frozen Protocol -> Motor A (evaluate) -> Motor B (verify + sign)
                                              |
                                              v
                                    Audit Chain (append-only,
                                    hash-chained, ML-DSA-65)
                                              |
                                              v
                                    Third-party verifier

## Quick start

    pip install -e .
    pytest

    from ai_claim_real import (
        RealPQCryptoModule, RealAuditChain,
        EvaluationEngine, AttestationEngine, AIClaimPipeline,
        verify_attestation,
    )
    import hashlib

    crypto = RealPQCryptoModule()
    signer = crypto.generate_keypair()
    chain = RealAuditChain(crypto=crypto, signer_keypair=signer)
    pipeline = AIClaimPipeline(EvaluationEngine(),
                                AttestationEngine(chain, crypto, signer))

    protocol = pipeline.register_protocol(
        chain, "credit-decision-v1", "1.0",
        {"max_amount_cents": 5_000_000, "requires_kyc": True, "currency": "USD"},
        evaluator_sha3=hashlib.sha3_512(b"eval_engine_src").hexdigest(),
        dataset_sha3=hashlib.sha3_512(b"ref_dataset").hexdigest(),
        seed=1,
    )

    result, attestation = pipeline.run(
        "credit-decision-v1",
        {"amount_cents": 2_500_000, "kyc_passed": True},
    )

    ok = verify_attestation(
        signer.public_key, crypto, protocol, result, attestation, chain,
    )
    print("verified:", ok)

## Adversarial Challenges

AI-CLAIM is tested by public adversarial challenges. Each challenge
documents the attacks attempted, the results, and any open gaps.

| Challenge | Attacks | GAP | Status |
|-----------|---------|-----|--------|
| #001 | 8 | 4 | Closed |
| #002 | 3 | 3 | Closed |
| #003 | 7 | 1 confirmed (version binding) | Version binding CLOSED |

The method is reproducible. The results include the gaps.

    from verify_bundle_standalone import to_bundle, run_adversarial_suite, print_adversarial_results
    bundle = to_bundle(protocol, result, attestation, chain, signer.public_key)
    results = run_adversarial_suite(bundle, signer.public_key.hex())
    print_adversarial_results(results)

Security findings: security@ai-claim.example before public disclosure.
30-day window.

## Regulatory mapping

AI-CLAIM's audit chain provides **SUPPORTING** evidence — never
**DIRECT** satisfaction — for 4 of the 230 official control objectives
of the FS AI RMF v1.0:

| Control | Description |
|---------|-------------|
| GV-6.2.4 | Monitoring and Early Warning |
| MS-2.7.4 | Security Metrics and Log Monitoring |
| MS-2.1.3 | Centralized TEVV Repository |
| MP-4.2.1 | Internal Controls for AI Components |

The underlying frameworks are the work of their respective bodies.
AI-CLAIM's own contribution is the code and the mapping methodology.

## Limits

- **No FIPS 140-3 certification.** Uses ML-DSA-65 via liboqs. Not
  certified by an accredited laboratory.
- **No external cryptographic audit.** Not reviewed by Trail of Bits,
  NCC Group, or any independent firm.
- **Private keys live in process memory.** For production, keys must
  reside in a certified HSM.
- **No ACVP/KAT vectors have been run.** Conformance to FIPS 204 is
  not claimed.
- **Identity binding is open.** A valid signature proves possession
  of a key, not authorization. Blocker for enterprise deployment.
- **The audit chain proves internal integrity, not uniqueness.**
  Detecting regeneration requires an external anchor.

## Roadmap

| Milestone | Target | Status |
|-----------|--------|--------|
| Version binding fix | 2026-10 | Done |
| NFC normalization | 2026-10 | Done |
| Error taxonomy | 2026-10 | Done |
| Identity binding | Q1 2027 | Design complete |
| External audit | Q2 2027 | Scoped |
| ACVP/KAT vectors | Q2 2027 | Framework ready |
| SOC 2 Type II | Q4 2027 | Not started |
| FIPS 140-3 path | 2028 | Not started |

## Licensing

- **Community Edition** (src/ai_claim_real/, tests/, demos,
  verifier): Apache 2.0.
- **Enterprise Edition**: Commercial license, distributed separately
  (identity binding, HSM integration, RFC 3161, key rotation,
  threshold signatures, RFC 8785 canonicalization, multi-tenancy).

## Contact

- **Issues**: https://github.com/[USERNAME]/ai-claim/issues
- **Security**: security@ai-claim.example
- **Commercial**: contact@ai-claim.example

## A note on the claims

Every number in this repository is a real number. Every "not certified"
and "not audited" is a real limitation. The regulatory mapping is
exactly what it says: 4 SUPPORTING, 0 DIRECT, of 230. The adversarial
challenges include the gaps. This repository publishes its own gaps
because that is the only credible way to be audited by a stranger.

— The AI-CLAIM project
