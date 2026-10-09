# ==============================================================================
# AI-CLAIM — Celda 19/22 (fix NFC + tests Challenge #003)
# TESTS DEL PAQUETE + verify.py
# ==============================================================================
import pathlib

TESTS = pathlib.Path("ai_claim_real_pkg/tests")
PKG_ROOT = pathlib.Path("ai_claim_real_pkg")
TESTS.mkdir(parents=True, exist_ok=True)

test_file = '''"""Tests del paquete ai_claim_real (API corregida + fixes #003)."""
import hashlib, time, unittest, unicodedata

from ai_claim_real import (RealPQCryptoModule, RealAuditChain,
                             FrozenProtocol, verify_protocol_registered,
                             EvaluationEngine, AttestationEngine, AIClaimPipeline,
                             EvaluationResult, verify_attestation,
                             RealSAFRGuard, issue_credential, verify_credential,
                             coverage_report)


def _sha(b):
    return hashlib.sha3_512(b).hexdigest()


class TestCrypto(unittest.TestCase):
    def setUp(self): self.crypto = RealPQCryptoModule()

    def test_algorithm(self):
        self.assertEqual(self.crypto.algorithm, "ML-DSA-65")

    def test_roundtrip(self):
        kp = self.crypto.generate_keypair()
        sig = self.crypto.sign(kp, b"test")
        self.assertTrue(self.crypto.verify(kp.public_key, b"test", sig))

    def test_tamper_detected(self):
        kp = self.crypto.generate_keypair()
        sig = self.crypto.sign(kp, b"orig")
        self.assertFalse(self.crypto.verify(kp.public_key, b"tampered", sig))

    def test_signature_size(self):
        kp = self.crypto.generate_keypair()
        self.assertGreater(len(self.crypto.sign(kp, b"x")), 3000)

    def test_no_fips_level_attribute(self):
        self.assertFalse(hasattr(self.crypto, "module_level"))
        self.assertFalse(hasattr(self.crypto, "FIPS_MODULE_LEVEL"))


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(self.crypto, self.signer)

    def test_empty_valid(self):
        self.assertTrue(self.chain.verify_chain()[0])

    def test_tamper_breaks_chain(self):
        for i in range(3): self.chain.append("test", {"i": i})
        self.chain.entries[1].payload["i"] = 999
        valid, broken = self.chain.verify_chain()
        self.assertFalse(valid); self.assertEqual(broken, 1)

    def test_rehash_forward_detected(self):
        for i in range(3): self.chain.append("test", {"i": i})
        e = self.chain.entries[1]
        e.payload["i"] = 999
        e.entry_hash = e.compute_hash()
        self.assertFalse(self.chain.verify_chain()[0])


class TestFrozenProtocolAndEngines(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(self.crypto, self.signer)
        self.pipeline = AIClaimPipeline(EvaluationEngine(),
            AttestationEngine(self.chain, self.crypto, self.signer))
        self.protocol = self.pipeline.register_protocol(
            self.chain, "credit-v1", "1.0", {"max_amount_cents": 5_000_000, "requires_kyc": True},
            evaluator_sha3=_sha(b"e"), dataset_sha3=_sha(b"d"), seed=1)

    def test_protocol_registered_in_chain(self):
        self.assertTrue(verify_protocol_registered(self.protocol, self.chain))

    def test_cannot_mutate_protocol(self):
        with self.assertRaises(Exception):
            self.protocol.rules_json = "{}"

    def test_approves_within_limits(self):
        r, _ = self.pipeline.run("credit-v1", {"amount_cents": 1_000_000, "kyc_passed": True})
        self.assertTrue(r.decision)

    def test_fails_closed_missing_field(self):
        r, _ = self.pipeline.run("credit-v1", {"kyc_passed": True})
        self.assertFalse(r.decision)

    def test_independent_verifier(self):
        r, att = self.pipeline.run("credit-v1", {"amount_cents": 100, "kyc_passed": True})
        self.assertTrue(verify_attestation(self.signer.public_key, self.crypto,
                                            self.protocol, r, att, self.chain))


class TestSAFR(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.issuer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(self.crypto, self.signer)
        self.pipeline = AIClaimPipeline(EvaluationEngine(),
            AttestationEngine(self.chain, self.crypto, self.signer))
        self.pipeline.register_protocol(self.chain, "safr-v1", "1.0",
            {"policies": {"agent-1": {"credit_decision": 5_000_000}},
             "requires_kyc": False, "currency": "USD"},
            evaluator_sha3=_sha(b"e"), dataset_sha3=_sha(b"d"), seed=1)
        self.guard = RealSAFRGuard(self.pipeline, self.crypto, self.issuer.public_key,
                                    protocol_id="safr-v1")
        self.cred = issue_credential(self.crypto, self.issuer, "agent-1", "m", "1.0",
                                      ["credit_decision"], {"credit_decision": 5_000_000}, "USD")

    def test_authorize_within_policy(self):
        permit, _ = self.guard.authorize(self.cred, "credit_decision", 1_000_000, "USD", "t")
        self.assertIsNotNone(permit)

    def test_reject_above_policy(self):
        permit, _ = self.guard.authorize(self.cred, "credit_decision", 9_000_000, "USD", "t")
        self.assertIsNone(permit)

    def test_permit_single_use(self):
        permit, _ = self.guard.authorize(self.cred, "credit_decision", 100, "USD", "t")
        self.assertTrue(self.guard.consume_permit(permit, "credit_decision", 100, "USD", "t", "agent-1"))
        self.assertFalse(self.guard.consume_permit(permit, "credit_decision", 100, "USD", "t", "agent-1"))


class TestRegulatory(unittest.TestCase):
    def test_honest_coverage(self):
        r = coverage_report()
        self.assertEqual(r["total_control_objectives_oficiales"], 230)
        self.assertEqual(r["candidatos_direct"], 0)
        self.assertGreater(r["candidatos_supporting"], 0)
        self.assertLess(r["candidatos_supporting"], 10)


class TestChallenge003Fixes(unittest.TestCase):
    """Verifica que los fixes del Challenge #003 cierran los ataques que los abrieron."""

    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(self.crypto, self.signer)
        self.pipeline = AIClaimPipeline(EvaluationEngine(),
            AttestationEngine(self.chain, self.crypto, self.signer))
        self.protocol = self.pipeline.register_protocol(
            self.chain, "credit-v1", "1.0",
            {"max_amount_cents": 5_000_000, "requires_kyc": True},
            evaluator_sha3=_sha(b"e"), dataset_sha3=_sha(b"d"), seed=1)

    def test_bundle_schema_version_is_signed(self):
        _, att = self.pipeline.run("credit-v1", {"amount_cents": 100, "kyc_passed": True})
        entry = self.chain.entries[att.chain_index]
        self.assertIn("bundle_schema_version", entry.payload)
        self.assertEqual(entry.payload["bundle_schema_version"], "4.0")

    def test_nfc_nfd_same_hash(self):
        nfc = unicodedata.normalize("NFC", "café")
        nfd = unicodedata.normalize("NFD", "café")
        self.assertNotEqual(nfc, nfd)
        r1 = EvaluationResult.compute("p" * 128, "i" * 128, True, 1.0, (nfc,))
        r2 = EvaluationResult.compute("p" * 128, "i" * 128, True, 1.0, (nfd,))
        self.assertEqual(r1.result_hash, r2.result_hash)

    def test_protocol_rules_normalization_match(self):
        rules_nfc = {"city": unicodedata.normalize("NFC", "São Paulo")}
        rules_nfd = {"city": unicodedata.normalize("NFD", "São Paulo")}
        p1 = FrozenProtocol.freeze(self.chain, "v1", "1.0", rules_nfc,
                                    evaluator_sha3=_sha(b"e"), dataset_sha3=_sha(b"d"), seed=1)
        p2 = FrozenProtocol.freeze(self.chain, "v2", "1.0", rules_nfd,
                                    evaluator_sha3=_sha(b"e"), dataset_sha3=_sha(b"d"), seed=2)
        self.assertEqual(p1.rules_json, p2.rules_json)


if __name__ == "__main__":
    unittest.main()
'''
(TESTS / "test_ai_claim_real.py").write_text(test_file)


verify_py = '''"""Verificacion post-instalacion."""
import hashlib, sys
from ai_claim_real import (RealPQCryptoModule, RealAuditChain, coverage_report, __version__)
from ai_claim_real.engines import EvaluationEngine, AttestationEngine, AIClaimPipeline
from ai_claim_real.safr import RealSAFRGuard, issue_credential


def main():
    print("=" * 60)
    print(f"AI-CLAIM v{__version__} — Verificacion (sin FIPS 140-3)")
    print("=" * 60)
    crypto = RealPQCryptoModule()
    signer = crypto.generate_keypair()
    issuer = crypto.generate_keypair()
    chain = RealAuditChain(crypto, signer)
    pipeline = AIClaimPipeline(EvaluationEngine(), AttestationEngine(chain, crypto, signer))
    pipeline.register_protocol(
        chain, "safr-verify-v1", "1.0",
        {"policies": {"verify-agent": {"credit_decision": 5_000_000}},
         "requires_kyc": False, "currency": "USD"},
        evaluator_sha3=hashlib.sha3_512(b"verify").hexdigest(),
        dataset_sha3=hashlib.sha3_512(b"n/a").hexdigest(), seed=1)
    guard = RealSAFRGuard(pipeline, crypto, issuer.public_key, protocol_id="safr-verify-v1")
    cred = issue_credential(crypto, issuer, "verify-agent", "model", "1.0",
                             ["credit_decision"], {"credit_decision": 5_000_000}, "USD")
    for amt in [2_500_000, 7_500_000]:
        permit, reason = guard.authorize(cred, "credit_decision", amt, "USD", "c")
        print(f"  amount_cents={amt:>10} -> permit={permit is not None} ({reason})")
    valid, _ = chain.verify_chain()
    cov = coverage_report(sample_chain=chain)
    print(f"\\n  Chain valid: {valid}")
    print(f"  Entries: {len(chain.entries)}")
    print(f"  Algorithm: {crypto.algorithm}")
    print(f"  FIPS 140-3 certified: NO")
    print(f"  FS AI RMF: {cov['total_control_objectives_oficiales']} "
          f"(SUPPORTING: {cov['candidatos_supporting']}, DIRECT: {cov['candidatos_direct']})")
    print("\\n" + "=" * 60)
    print("  Verificado")
    print("=" * 60)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
'''
(PKG_ROOT / "verify.py").write_text(verify_py)

print("=" * 78)
print("  TESTS Y VERIFICACIÓN DEL PAQUETE — API corregida + Challenge #003")
print("=" * 78)
for f in sorted(PKG_ROOT.rglob("*")):
    if f.is_file():
        rel = f.relative_to(PKG_ROOT)
        print(f"    {str(rel):48} ({f.stat().st_size:,} bytes)")
print("\n  Uso: cd ai_claim_real_pkg && pip install -e .[dev] && pytest && python verify.py")
print("=" * 78)
