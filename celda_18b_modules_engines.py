# ==============================================================================
# AI-CLAIM — Celda 18b/22 (fix NFC + version binding aplicados)
# MÓDULOS DEL PAQUETE: engines.py, safr.py
# ==============================================================================
import pathlib

SRC = pathlib.Path("ai_claim_real_pkg/src/ai_claim_real")

engines_py = '''"""Motor A + Motor B con NFC y bundle_schema_version firmado."""
import hashlib, json, time, unicodedata
from dataclasses import dataclass
from typing import Any, Dict, Tuple
from .protocol import FrozenProtocol

_DOMAIN_RESULT = b"AI-CLAIM/eval-result/v1\\x00"


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
            return self._rejected(protocol, input_hash, "protocolo alterado o invalido")
        amount = input_data.get("amount_cents")
        kyc_passed = input_data.get("kyc_passed", False)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            return self._rejected(protocol, input_hash, "amount_cents ausente o invalido")
        import json as _j
        rules = _j.loads(protocol.rules_json)
        if "policies" in rules:
            agent_id = input_data.get("agent_id")
            action_type = input_data.get("action_type")
            if not isinstance(agent_id, str) or not isinstance(action_type, str):
                return self._rejected(protocol, input_hash, "agent_id/action_type invalido")
            limit = rules["policies"].get(agent_id, {}).get(action_type)
            if not isinstance(limit, int):
                return self._rejected(protocol, input_hash,
                                       f"sin politica para agente={agent_id} accion={action_type}")
            requires_kyc = rules.get("requires_kyc", True)
        else:
            if not isinstance(kyc_passed, bool):
                return self._rejected(protocol, input_hash, "kyc_passed ausente o invalido")
            limit = rules.get("max_amount_cents")
            requires_kyc = rules.get("requires_kyc", True)
            if not isinstance(limit, int):
                return self._rejected(protocol, input_hash, "protocolo sin max_amount_cents valido")
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
        if not protocol.verify(): raise ValueError("protocolo invalido — no se firma")
        if not result.verify(): raise ValueError("resultado inconsistente — no se firma")
        if protocol.protocol_hash != result.protocol_hash:
            raise ValueError("protocol_hash no coincide")
        entry = self._chain.append("attested_evaluation", {
            "bundle_schema_version": bundle_schema_version,
            "protocol_id": protocol.protocol_id, "protocol_hash": protocol.protocol_hash,
            "result_hash": result.result_hash, "input_hash": result.input_hash,
            "decision": result.decision, "score": result.score,
            "reasons": list(result.reasons)})
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
'''
(SRC / "engines.py").write_text(engines_py)


safr_py = '''"""Guardia SAFR con NFC."""
import hashlib, json, secrets, time, unicodedata
from dataclasses import dataclass
from typing import Dict, Set

_DOMAIN_CRED = b"AI-CLAIM/agent-credential/v1\\x00"
_DOMAIN_ACTION = b"AI-CLAIM/agent-action/v1\\x00"


def _nfc(obj):
    if isinstance(obj, str): return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict): return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)): return [_nfc(x) for x in obj]
    return obj


def _canon_str_safr(obj) -> str:
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class AgentCredential:
    agent_id: str
    model_id: str
    version: str
    permissions: tuple
    risk_limits_cents: Dict[str, int]
    currency: str
    issued_at: float
    expires_at: float
    signature: str

    def canonical_body(self):
        body = {"agent_id": self.agent_id, "model_id": self.model_id, "version": self.version,
                "permissions": list(self.permissions), "risk_limits_cents": self.risk_limits_cents,
                "currency": self.currency, "issued_at": self.issued_at, "expires_at": self.expires_at}
        return _DOMAIN_CRED + _canon_str_safr(body).encode()

    def valid_now(self):
        return self.issued_at <= time.time() < self.expires_at


def issue_credential(crypto, issuer_keypair, agent_id, model_id, version,
                      permissions, risk_limits_cents, currency, ttl_seconds=3600):
    now = time.time()
    c = AgentCredential(agent_id, model_id, version, tuple(permissions),
                         dict(risk_limits_cents), currency, now, now + ttl_seconds, "")
    sig = crypto.sign(issuer_keypair, c.canonical_body())
    return AgentCredential(**{**c.__dict__, "signature": sig.hex()})


def verify_credential(crypto, issuer_public_key, cred):
    if not cred.valid_now(): return False
    return crypto.verify(issuer_public_key, cred.canonical_body(), bytes.fromhex(cred.signature))


@dataclass(frozen=True)
class Permit:
    action_hash: str
    entry_hash: str
    nonce: str
    expires_at: float

    def valid_now(self):
        return time.time() < self.expires_at


class RealSAFRGuard:
    def __init__(self, pipeline, crypto, issuer_public_key, protocol_id="safr-protocol-v1"):
        self._pipeline, self._crypto, self._issuer_pub = pipeline, crypto, issuer_public_key
        self._used_nonces: Set[str] = set()
        self._protocol_id = protocol_id

    def set_protocol_id(self, protocol_id):
        self._protocol_id = protocol_id

    def authorize(self, cred, action_type, amount_cents, currency, target):
        if not verify_credential(self._crypto, self._issuer_pub, cred):
            return None, "credencial invalida"
        if action_type not in cred.permissions:
            return None, f"accion '{action_type}' no autorizada"
        if currency != cred.currency:
            return None, f"moneda no coincide"
        try:
            result, attestation = self._pipeline.run(self._protocol_id, {
                "agent_id": cred.agent_id, "action_type": action_type,
                "amount_cents": amount_cents, "currency": currency, "target": target})
        except Exception as e:
            return None, f"error interno ({e})"
        if not result.decision:
            return None, f"denegado: {result.reasons}"
        body = {"agent_id": cred.agent_id, "action_type": action_type,
                "amount_cents": amount_cents, "currency": currency, "target": target}
        ah = hashlib.sha3_512(_DOMAIN_ACTION + _canon_str_safr(body).encode()).hexdigest()
        return Permit(ah, attestation.chain_entry_hash, secrets.token_hex(16),
                       time.time() + 60), "autorizado"

    def consume_permit(self, permit, action_type, amount_cents, currency, target, agent_id):
        if permit.nonce in self._used_nonces or not permit.valid_now(): return False
        body = {"agent_id": agent_id, "action_type": action_type,
                "amount_cents": amount_cents, "currency": currency, "target": target}
        expected = hashlib.sha3_512(_DOMAIN_ACTION + _canon_str_safr(body).encode()).hexdigest()
        if expected != permit.action_hash: return False
        self._used_nonces.add(permit.nonce)
        return True
'''
(SRC / "safr.py").write_text(safr_py)

print("[OK] Celda 18b — engines.py, safr.py (fix NFC + version binding)")
