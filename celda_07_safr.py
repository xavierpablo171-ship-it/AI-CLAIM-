# ==============================================================================
# AI-CLAIM — Celda 7/22 (fix NFC aplicado)
# GUARDIA SAFR: credenciales firmadas + permisos de un solo uso
# ==============================================================================
import hashlib, json, secrets, time, unicodedata
from dataclasses import dataclass
from typing import Dict, Set

_DOMAIN_CRED = b"AI-CLAIM/agent-credential/v1\x00"
_DOMAIN_ACTION = b"AI-CLAIM/agent-action/v1\x00"


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

    def canonical_body(self) -> bytes:
        body = {"agent_id": self.agent_id, "model_id": self.model_id, "version": self.version,
                "permissions": list(self.permissions), "risk_limits_cents": self.risk_limits_cents,
                "currency": self.currency, "issued_at": self.issued_at, "expires_at": self.expires_at}
        return _DOMAIN_CRED + _canon_str_safr(body).encode()

    def valid_now(self) -> bool:
        return self.issued_at <= time.time() < self.expires_at


def issue_credential(crypto, issuer_keypair, agent_id, model_id, version,
                      permissions, risk_limits_cents, currency, ttl_seconds=3600):
    now = time.time()
    c = AgentCredential(agent_id, model_id, version, tuple(permissions),
                         dict(risk_limits_cents), currency, now, now + ttl_seconds, "")
    sig = crypto.sign(issuer_keypair, c.canonical_body())
    return AgentCredential(**{**c.__dict__, "signature": sig.hex()})


def verify_credential(crypto, issuer_public_key, cred) -> bool:
    if not cred.valid_now(): return False
    return crypto.verify(issuer_public_key, cred.canonical_body(), bytes.fromhex(cred.signature))


@dataclass(frozen=True)
class Permit:
    action_hash: str
    entry_hash: str
    nonce: str
    expires_at: float

    def valid_now(self) -> bool:
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
            return None, "credencial inválida, expirada o no verificable"
        if action_type not in cred.permissions:
            return None, f"acción '{action_type}' no autorizada"
        if currency != cred.currency:
            return None, f"moneda '{currency}' no coincide"
        try:
            result, attestation = self._pipeline.run(self._protocol_id, {
                "agent_id": cred.agent_id, "action_type": action_type,
                "amount_cents": amount_cents, "currency": currency, "target": target})
        except Exception as e:
            return None, f"error interno — denegado ({e})"
        if not result.decision:
            return None, f"denegado por protocolo: {result.reasons}"
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


import hashlib as _h

crypto = RealPQCryptoModule()
signer = crypto.generate_keypair()
issuer = crypto.generate_keypair()
chain = RealAuditChain(crypto=crypto, signer_keypair=signer)
pipeline = AIClaimPipeline(EvaluationEngine(), AttestationEngine(chain, crypto, signer))

AGENT_ID = "credit-agent-007"
pipeline.register_protocol(
    chain, "safr-protocol-v1", "1.0.0",
    {"policies": {AGENT_ID: {"credit_decision": 5_000_000, "fraud_check": 100_000_000}},
     "requires_kyc": False, "currency": "USD"},
    evaluator_sha3=_h.sha3_512(b"safr_eval_src").hexdigest(),
    dataset_sha3=_h.sha3_512(b"n/a").hexdigest(), seed=1)

guard = RealSAFRGuard(pipeline, crypto, issuer_public_key=issuer.public_key)
cred = issue_credential(crypto, issuer, AGENT_ID, "risk-scoring-v3", "3.2.1",
    permissions=["credit_decision", "fraud_check"],
    risk_limits_cents={"credit_decision": 5_000_000, "fraud_check": 100_000_000},
    currency="USD")

permit, reason = guard.authorize(cred, "credit_decision", 2_500_000, "USD", "customer-4521")
print(f"Dentro de límites -> permit={permit is not None}, razón={reason}")
if permit:
    print(f"  Consumido: {guard.consume_permit(permit, 'credit_decision', 2_500_000, 'USD', 'customer-4521', cred.agent_id)}")
    print(f"  Reintento (debe fallar): {guard.consume_permit(permit, 'credit_decision', 2_500_000, 'USD', 'customer-4521', cred.agent_id)}")
permit2, reason2 = guard.authorize(cred, "payment", 1_000_00, "USD", "vendor-998")
print(f"Acción no autorizada -> permit={permit2 is not None}, razón={reason2}")
