# ==============================================================================
# AI-CLAIM — Celda 11/22 (fix NFC + tests Challenge #003 aplicados)
# SUITE DE TESTS contra la API corregida
# ==============================================================================
import time, unittest, hashlib, unicodedata


class TestRealCrypto(unittest.TestCase):
    def setUp(self): self.crypto = RealPQCryptoModule()

    def test_sign_verify_roundtrip(self):
        kp = self.crypto.generate_keypair()
        sig = self.crypto.sign(kp, b"test message")
        self.assertTrue(self.crypto.verify(kp.public_key, b"test message", sig))

    def test_rejects_tampered_message(self):
        kp = self.crypto.generate_keypair()
        sig = self.crypto.sign(kp, b"original")
        self.assertFalse(self.crypto.verify(kp.public_key, b"tampered", sig))

    def test_rejects_wrong_key(self):
        kp1 = self.crypto.generate_keypair(); kp2 = self.crypto.generate_keypair()
        sig = self.crypto.sign(kp1, b"msg")
        self.assertFalse(self.crypto.verify(kp2.public_key, b"msg", sig))

    def test_signature_and_key_sizes(self):
        kp = self.crypto.generate_keypair()
        sig = self.crypto.sign(kp, b"test")
        self.assertTrue(3000 < len(sig) < 3500)
        self.assertTrue(1800 < len(kp.public_key) < 2100)


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(crypto=self.crypto, signer_keypair=self.signer)

    def test_empty_chain_valid(self):
        valid, broken = self.chain.verify_chain()
        self.assertTrue(valid); self.assertIsNone(broken)

    def test_naive_tampering_detected(self):
        for i in range(5): self.chain.append("test", {"amount": 100 + i})
        self.chain.entries[2].payload["amount"] = 999999
        valid, broken = self.chain.verify_chain()
        self.assertFalse(valid); self.assertEqual(broken, 2)

    def test_rehash_forward_attack_detected(self):
        for i in range(5): self.chain.append("test", {"amount": 100 + i})
        e = self.chain.entries[2]
        e.payload["amount"] = 999999
        e.entry_hash = e.compute_hash()
        valid, broken = self.chain.verify_chain()
        self.assertFalse(valid, "rehash-forward NO detectado — bug crítico")
        self.assertEqual(broken, 2)

    def test_truncation_detected_with_anchor(self):
        for i in range(5): self.chain.append("test", {"i": i})
        real_head = self.chain.head
        self.assertTrue(self.chain.verify_chain(expected_head=real_head)[0])
        self.assertFalse(self.chain.verify_chain(expected_head="f" * 128)[0])


class TestFrozenProtocol(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(crypto=self.crypto, signer_keypair=self.signer)

    def test_freeze_and_verify(self):
        p = FrozenProtocol.freeze(self.chain, "p1", "1.0", {"max_amount_cents": 1000},
                                    evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)
        self.assertTrue(p.verify())
        self.assertTrue(verify_protocol_registered(p, self.chain))

    def test_cannot_mutate_frozen_protocol(self):
        p = FrozenProtocol.freeze(self.chain, "p2", "1.0", {"max_amount_cents": 1000},
                                    evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)
        with self.assertRaises(Exception):
            p.rules_json = '{"max_amount_cents": 999999999}'

    def test_forged_protocol_with_reused_hash_fails_verify(self):
        p = FrozenProtocol.freeze(self.chain, "p3", "1.0", {"max_amount_cents": 1000},
                                    evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)
        forged = FrozenProtocol(protocol_id=p.protocol_id, version=p.version,
            rules_json='{"max_amount_cents": 999999999}',
            evaluator_sha3=p.evaluator_sha3, dataset_sha3=p.dataset_sha3,
            seed=p.seed, nonce=p.nonce, frozen_at=p.frozen_at,
            protocol_hash=p.protocol_hash, chain_index=p.chain_index)
        self.assertFalse(forged.verify())


class TestTwoEngines(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(crypto=self.crypto, signer_keypair=self.signer)
        self.pipeline = AIClaimPipeline(EvaluationEngine(),
            AttestationEngine(self.chain, self.crypto, self.signer))
        self.protocol = self.pipeline.register_protocol(
            self.chain, "credit-v1", "1.0",
            {"max_amount_cents": 5_000_000, "requires_kyc": True},
            evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)

    def test_approves_within_limits(self):
        r, _ = self.pipeline.run("credit-v1", {"amount_cents": 1_000_000, "kyc_passed": True})
        self.assertTrue(r.decision)

    def test_rejects_above_limit(self):
        r, _ = self.pipeline.run("credit-v1", {"amount_cents": 9_000_000, "kyc_passed": True})
        self.assertFalse(r.decision)

    def test_fails_closed_on_missing_field(self):
        r, _ = self.pipeline.run("credit-v1", {"kyc_passed": True})
        self.assertFalse(r.decision)

    def test_fails_closed_on_negative_amount(self):
        r, _ = self.pipeline.run("credit-v1", {"amount_cents": -500, "kyc_passed": True})
        self.assertFalse(r.decision)

    def test_forged_result_fails_verify(self):
        real, _ = self.pipeline.run("credit-v1", {"amount_cents": 100, "kyc_passed": True})
        forged = EvaluationResult(protocol_hash=real.protocol_hash, input_hash=real.input_hash,
            decision=True, score=1.0, reasons=("forjado",),
            evaluated_at=real.evaluated_at, result_hash=real.result_hash)
        self.assertFalse(forged.verify())

    def test_independent_verifier_accepts_real_attestation(self):
        r, att = self.pipeline.run("credit-v1", {"amount_cents": 100, "kyc_passed": True})
        self.assertTrue(verify_attestation(self.signer.public_key, self.crypto,
                                            self.protocol, r, att, self.chain))


class TestSAFRGuard(unittest.TestCase):
    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.issuer = self.crypto.generate_keypair()
        self.other_issuer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(crypto=self.crypto, signer_keypair=self.signer)
        self.pipeline = AIClaimPipeline(EvaluationEngine(),
            AttestationEngine(self.chain, self.crypto, self.signer))
        self.pipeline.register_protocol(self.chain, "safr-protocol-v1", "1.0",
            {"policies": {"agent-1": {"credit_decision": 5_000_000}},
             "requires_kyc": False, "currency": "USD"},
            evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)
        self.guard = RealSAFRGuard(self.pipeline, self.crypto, issuer_public_key=self.issuer.public_key)
        self.cred = issue_credential(self.crypto, self.issuer, "agent-1", "model-x", "1.0",
            permissions=["credit_decision"], risk_limits_cents={"credit_decision": 5_000_000},
            currency="USD", ttl_seconds=2)

    def test_rejects_credential_from_untrusted_issuer(self):
        fake = issue_credential(self.crypto, self.other_issuer, "agent-1", "model-x", "1.0",
            permissions=["credit_decision"], risk_limits_cents={"credit_decision": 5_000_000},
            currency="USD")
        self.assertFalse(verify_credential(self.crypto, self.issuer.public_key, fake))

    def test_rejects_expired_credential(self):
        time.sleep(2.1)
        permit, reason = self.guard.authorize(self.cred, "credit_decision", 100, "USD", "t1")
        self.assertIsNone(permit)

    def test_rejects_currency_mismatch(self):
        permit, _ = self.guard.authorize(self.cred, "credit_decision", 100, "EUR", "t1")
        self.assertIsNone(permit)

    def test_permit_cannot_be_reused(self):
        permit, _ = self.guard.authorize(self.cred, "credit_decision", 100, "USD", "t1")
        self.assertIsNotNone(permit)
        first = self.guard.consume_permit(permit, "credit_decision", 100, "USD", "t1", "agent-1")
        second = self.guard.consume_permit(permit, "credit_decision", 100, "USD", "t1", "agent-1")
        self.assertTrue(first); self.assertFalse(second, "permiso reutilizado")


class TestChallenge003Fixes(unittest.TestCase):
    """Verifica que los fixes del Challenge #003 cierran los ataques que los abrieron."""

    def setUp(self):
        self.crypto = RealPQCryptoModule()
        self.signer = self.crypto.generate_keypair()
        self.chain = RealAuditChain(crypto=self.crypto, signer_keypair=self.signer)
        self.pipeline = AIClaimPipeline(EvaluationEngine(),
            AttestationEngine(self.chain, self.crypto, self.signer))
        self.protocol = self.pipeline.register_protocol(
            self.chain, "credit-v1", "1.0",
            {"max_amount_cents": 5_000_000, "requires_kyc": True},
            evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)

    def test_bundle_schema_version_is_signed(self):
        _, att = self.pipeline.run("credit-v1", {"amount_cents": 100, "kyc_passed": True})
        entry = self.chain.entries[att.chain_index]
        self.assertIn("bundle_schema_version", entry.payload)
        self.assertEqual(entry.payload["bundle_schema_version"], "4.0")

    def test_nfc_and_nfd_produce_same_hash(self):
        nfc_text = unicodedata.normalize("NFC", "café")
        nfd_text = unicodedata.normalize("NFD", "café")
        self.assertNotEqual(nfc_text, nfd_text)
        r1 = EvaluationResult.compute("p" * 128, "i" * 128, True, 1.0, (nfc_text,))
        r2 = EvaluationResult.compute("p" * 128, "i" * 128, True, 1.0, (nfd_text,))
        self.assertEqual(r1.result_hash, r2.result_hash)

    def test_protocol_rules_with_different_normalization_match(self):
        rules_nfc = {"city": unicodedata.normalize("NFC", "São Paulo")}
        rules_nfd = {"city": unicodedata.normalize("NFD", "São Paulo")}
        p1 = FrozenProtocol.freeze(self.chain, "v1", "1.0", rules_nfc,
                                    evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=1)
        p2 = FrozenProtocol.freeze(self.chain, "v2", "1.0", rules_nfd,
                                    evaluator_sha3="e" * 128, dataset_sha3="d" * 128, seed=2)
        self.assertEqual(p1.rules_json, p2.rules_json)


def _run():
    print("=" * 78)
    print("  SUITE DE TESTS — API corregida + fixes Challenge #003")
    print("=" * 78)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [TestRealCrypto, TestAuditChain, TestFrozenProtocol,
                TestTwoEngines, TestSAFRGuard, TestChallenge003Fixes]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("\n" + "=" * 78)
    print(f"  {result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors")
    print(f"  ESTADO: {'PASS' if result.wasSuccessful() else 'FAIL'}")
    print("=" * 78)
    return result


_run()
