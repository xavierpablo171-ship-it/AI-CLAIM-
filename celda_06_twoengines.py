# ==============================================================================
# AI-CLAIM — Celda 6/22 (fix NFC + version binding aplicados)
# DOS MOTORES: Motor A (evaluación) + Motor B (atestación)
# bundle_schema_version va DENTRO del payload firmado (cierra GAP #003)
# ==============================================================================
import hashlib, json, time, unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

_DOMAIN_RESULT = b"AI-CLAIM/eval-result/v1\x00"


def _nfc(obj):
    if isinstance(obj, str): return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict): return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)): return [_nfc(x) for x in obj]
    return obj


def _canon_str_result(obj) -> str:
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class EvaluationResult:
    protocol_hash: str
    input_hash: str
    decision: bool
    score: float
    reasons: Tuple[str, ...]
    evaluated_at: float
    result_hash: str

    @staticmethod
    def compute(protocol_hash, input_hash, decision, score, reasons):
        body = {"protocol_hash": protocol_hash, "input_hash": input_hash,
                "decision": decision, "score": score, "reasons": list(reasons)}
        h = hashlib.sha3_512(_DOMAIN_RESULT + _canon_str_result(body).encode()).hexdigest()
        return EvaluationResult(protocol_hash, input_hash, decision, score,
                                 tuple(reasons), time.time(), h)

    def verify(self):
        body = {"protocol_hash": self.protocol_hash, "input_hash": self.input_hash,
                "decision": self.decision, "score": self.score, "reasons": list(self.reasons)}
        expected = hashlib.sha3_512(_DOMAIN_RESULT + _canon_str_result(body).encode()).hexdigest()
        return expected == self.result_hash


@dataclass(frozen=True)
class Attestation:
    protocol_hash: str
    result_hash: str
    chain_index: int
    chain_entry_hash: str
    attested_at: float
    signature: str


class EvaluationEngine:
    def __init__(self):
        self.evaluations = 0

    def _rejected(self, protocol, input_hash, reason):
        return EvaluationResult.compute(protocol.protocol_hash, input_hash, False, 0.0, (reason,))

    def evaluate(self, protocol, input_data):
        input_hash = hashlib.sha3_512(_canon_str_result(input_data).encode()).hexdigest()
        self.evaluations += 1
        if not protocol.verify():
            return self._rejected(protocol, input_hash, "protocolo alterado o inválido")
        amount = input_data.get("amount_cents")
        kyc_passed = input_data.get("kyc_passed", False)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            return self._rejected(protocol, input_hash, "amount_cents ausente o inválido")
        rules = json.loads(protocol.rules_json)
        if "policies" in rules:
            agent_id = input_data.get("agent_id")
            action_type = input_data.get("action_type")
            if not isinstance(agent_id, str) or not isinstance(action_type, str):
                return self._rejected(protocol, input_hash, "agent_id/action_type inválido")
            limit = rules["policies"].get(agent_id, {}).get(action_type)
            if not isinstance(limit, int):
                return self._rejected(protocol, input_hash,
                                       f"sin política para agente={agent_id} accion={action_type}")
            requires_kyc = rules.get("requires_kyc", True)
        else:
            if not isinstance(kyc_passed, bool):
                return self._rejected(protocol, input_hash, "kyc_passed inválido")
            limit = rules.get("max_amount_cents")
            requires_kyc = rules.get("requires_kyc", True)
            if not isinstance(limit, int):
                return self._rejected(protocol, input_hash, "protocolo sin max_amount_cents")
        reasons, decision = [], True
        if amount > limit:
            decision = False; reasons.append(f"amount_cents {amount} excede limite {limit}")
        if requires_kyc and not kyc_passed:
            decision = False; reasons.append("KYC requerido y no aprobado")
        if decision:
            reasons.append("condiciones del protocolo satisfechas")
        return EvaluationResult.compute(protocol.protocol_hash, input_hash, decision,
                                         1.0 if decision else 0.0, tuple(reasons))


class AttestationEngine:
    def __init__(self, chain, crypto, signer):
        self._chain, self._crypto, self._signer = chain, crypto, signer
        self.attestations = 0

    def attest(self, protocol, result, bundle_schema_version="4.0"):
        if not protocol.verify():
            raise ValueError("protocolo inválido — no se firma")
        if not result.verify():
            raise ValueError("resultado inconsistente — no se firma")
        if protocol.protocol_hash != result.protocol_hash:
            raise ValueError("protocol_hash no coincide")
        entry = self._chain.append("attested_evaluation", {
            "bundle_schema_version": bundle_schema_version,
            "protocol_id": protocol.protocol_id,
            "protocol_hash": protocol.protocol_hash,
            "result_hash": result.result_hash,
            "input_hash": result.input_hash,
            "decision": result.decision,
            "score": result.score,
            "reasons": list(result.reasons),
        })
        self.attestations += 1
        return Attestation(protocol.protocol_hash, result.result_hash, entry.index,
                            entry.entry_hash, entry.timestamp, entry.signature)


def verify_attestation(trusted_public_key, crypto, protocol, result, att, chain):
    if not protocol.verify() or not result.verify(): return False
    if att.protocol_hash != protocol.protocol_hash or att.result_hash != result.result_hash:
        return False
    if att.chain_index >= len(chain.entries): return False
    entry = chain.entries[att.chain_index]
    if entry.entry_hash != att.chain_entry_hash or entry.signature != att.signature:
        return False
    return crypto.verify(trusted_public_key, entry.canonical(), bytes.fromhex(entry.signature))


class AIClaimPipeline:
    def __init__(self, evaluation_engine, attestation_engine):
        self.evaluator, self.attestor, self.protocols = evaluation_engine, attestation_engine, {}

    def register_protocol(self, chain, protocol_id, version, rules,
                           evaluator_sha3, dataset_sha3, seed):
        if protocol_id in self.protocols:
            raise ValueError(f"protocolo '{protocol_id}' ya registrado")
        p = FrozenProtocol.freeze(chain, protocol_id, version, rules,
                                   evaluator_sha3, dataset_sha3, seed)
        self.protocols[protocol_id] = p
        return p

    def run(self, protocol_id, input_data):
        p = self.protocols.get(protocol_id)
        if p is None: raise KeyError(f"protocolo {protocol_id} no registrado")
        result = self.evaluator.evaluate(p, input_data)
        return result, self.attestor.attest(p, result)


import hashlib as _h

crypto = RealPQCryptoModule()
signer = crypto.generate_keypair()
chain = RealAuditChain(crypto=crypto, signer_keypair=signer)
evaluator = EvaluationEngine()
attestor = AttestationEngine(chain=chain, crypto=crypto, signer=signer)
pipeline = AIClaimPipeline(evaluator, attestor)

protocol = pipeline.register_protocol(
    chain, "credit-decision-v1", "1.0.0",
    {"max_amount_cents": 5_000_000, "requires_kyc": True, "currency": "USD"},
    evaluator_sha3=_h.sha3_512(b"eval_engine_src").hexdigest(),
    dataset_sha3=_h.sha3_512(b"ref_dataset").hexdigest(), seed=1)

for inp in [{"amount_cents": 2_500_000, "kyc_passed": True},
            {"amount_cents": 7_500_000, "kyc_passed": True},
            {"amount_cents": 4_000_000, "kyc_passed": False},
            {"kyc_passed": True}]:
    result, att = pipeline.run("credit-decision-v1", inp)
    print(f"input={inp} -> decision={result.decision}")

ok = verify_attestation(signer.public_key, crypto, protocol, result, att, chain)
print(f"\nVerificación independiente: {ok}")
print(f"bundle_schema_version firmado: {chain.entries[att.chain_index].payload.get('bundle_schema_version')}")
