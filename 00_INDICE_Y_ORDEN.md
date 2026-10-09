# AI-CLAIM — Index and Execution Order (October 2026, post-Challenge #003)

## Core — run in this order, same Colab session, without restart

01. celda_01_crypto.py             — ML-DSA-65 via liboqs
02. celda_02_crossverify.py        — OpenSSL cross-verification (honest AND gate)
03. celda_03_hsm.py                — PKCS#11/SoftHSM2 (RSA-2048, not ML-DSA)
04. celda_04_auditchain.py         — chain + signatures + NFC
05. celda_05_frozenprotocol.py     — frozen protocol + NFC
06. celda_06_twoengines.py         — Motor A/B + NFC + version binding
07. celda_07_safr.py               — SAFR guard + NFC
08. celda_08_regmapping.py         — FS AI RMF mapping (230 official, 4 SUPPORTING)
09. celda_09_solana.py             — Solana memo adapter
10. celda_10_benchmark.py          — benchmark n=10,000
11. celda_11_tests.py              — test suite + TestChallenge003Fixes
12. celda_12_report.py             — HTML report
13. celda_13_pdf.py                — PDF export

## Service and deployment (separate context — Docker)

14. celda_14_service.py            — FastAPI with signed credentials + API key
15. celda_15_stack.py              — docker-compose with reduced DB privileges

## Installable package

17. celda_17_pkgmeta.py            — pyproject/README/LICENSE, version 0.1.0
18. celda_18a_modules_core.py      — crypto/audit/protocol + NFC
19. celda_18b_modules_engines.py   — engines/safr + NFC + version binding
20. celda_18c_modules_reg_cli.py   — regulatory/__init__/cli
21. celda_19_pkgtests.py           — tests + TestChallenge003Fixes
22. celda_20_wheel.py              — build + GPG
23. celda_21_dockerverify.py       — clean Docker verification
24. celda_22_legal.py              — LICENSE, NDA, IP inventory

## Standalone

- verify_bundle_standalone.py      — portable bundle + verifier (v5)
- demo_motor_a_llm_juicio.py       — Claude as Motor A (req. 01,04,05,06)
- demo_autocontenida_motor_a.py    — self-contained core demo

## Challenge #003 status (Oct 2026)

- Version downgrade: CLOSED (bundle_schema_version signed)
- Unicode NFC/NFD:   CLOSED (recursive normalization)
- Signature trunc.:  PASS (real liboqs pending)
- Simulated backend: INCONCLUSIVE (requires real liboqs)
- Identity binding:  OPEN — CRITICAL
- Critical fields:   PARTIAL (formal enumeration pending)
- Indep. verif.:     PASS (demo)

## Version notes

- Cell 2 in real Colab reported OpenSSL 3.0.13 without native ML-DSA
  -> cross-verify unavailable, not a bug.
- oqs.py used in the validation sandbox is a stub; in Colab with real
  liboqs it is real cryptography.
- Challenge #003 fixes are applied in: 04, 05, 06, 07, 11, 18a, 18b,
  19, verify_bundle_standalone.py, demo_motor_a_llm_juicio.py,
  demo_autocontenida_motor_a.py.
