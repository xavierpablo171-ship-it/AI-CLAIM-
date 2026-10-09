# ==============================================================================
# AI-CLAIM — Celda 5/22 (fix NFC aplicado)
# PROTOCOLO CONGELADO: garantía anti-p-hacking
# ==============================================================================
import hashlib, json, secrets, time, unicodedata
from dataclasses import dataclass

_DOMAIN_PROTOCOL = b"AI-CLAIM/protocol/v1\x00"


def _nfc(obj):
    if isinstance(obj, str): return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict): return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)): return [_nfc(x) for x in obj]
    return obj


def _canon_str_protocol(obj) -> str:
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash_body(body):
    return hashlib.sha3_512(_DOMAIN_PROTOCOL + _canon_str_protocol(body).encode()).hexdigest()


@dataclass(frozen=True)
class FrozenProtocol:
    protocol_id: str
    version: str
    rules_json: str
    evaluator_sha3: str
    dataset_sha3: str
    seed: int
    nonce: str
    frozen_at: float
    protocol_hash: str
    chain_index: int

    def verify(self) -> bool:
        body = {"protocol_id": self.protocol_id, "version": self.version,
                "rules_json": self.rules_json, "evaluator_sha3": self.evaluator_sha3,
                "dataset_sha3": self.dataset_sha3, "seed": self.seed, "nonce": self.nonce}
        return _hash_body(body) == self.protocol_hash

    @classmethod
    def freeze(cls, chain, protocol_id, version, rules,
               evaluator_sha3, dataset_sha3, seed) -> "FrozenProtocol":
        rules_json = _canon_str_protocol(rules)
        nonce = secrets.token_hex(16)
        body = {"protocol_id": protocol_id, "version": version, "rules_json": rules_json,
                "evaluator_sha3": evaluator_sha3, "dataset_sha3": dataset_sha3,
                "seed": seed, "nonce": nonce}
        ph = _hash_body(body)
        entry = chain.append("protocol_frozen",
                             {"protocol_hash": ph, "protocol_id": protocol_id, "version": version})
        return cls(protocol_id=protocol_id, version=version, rules_json=rules_json,
                    evaluator_sha3=evaluator_sha3, dataset_sha3=dataset_sha3, seed=seed,
                    nonce=nonce, frozen_at=time.time(), protocol_hash=ph,
                    chain_index=entry.index)


def verify_protocol_registered(protocol, chain) -> bool:
    if not protocol.verify() or protocol.chain_index >= len(chain.entries):
        return False
    entry = chain.entries[protocol.chain_index]
    return (entry.event_type == "protocol_frozen"
            and entry.payload.get("protocol_hash") == protocol.protocol_hash
            and chain.verify_signature(entry))


def _run(chain):
    print("=" * 78)
    print("  PROTOCOLO CONGELADO")
    print("=" * 78)
    p = FrozenProtocol.freeze(
        chain, "credit-decision-v1", "1.0.0",
        {"max_amount_cents": 5_000_000, "requires_kyc": True, "currency": "USD"},
        evaluator_sha3=hashlib.sha3_512(b"eval_src").hexdigest(),
        dataset_sha3=hashlib.sha3_512(b"ref_dataset").hexdigest(), seed=42)
    print(f"  Hash: {p.protocol_hash[:48]}...")
    print(f"  Registrado en cadena idx: {p.chain_index}")
    print(f"  verify_protocol_registered: {verify_protocol_registered(p, chain)}")
    try:
        p.rules_json = '{"max_amount_cents": 500000000}'
        print("  MUTÓ — bug crítico")
    except Exception as e:
        print(f"  Mutación bloqueada: {type(e).__name__}")
    forged = FrozenProtocol(
        protocol_id=p.protocol_id, version=p.version,
        rules_json='{"currency":"USD","max_amount_cents":500000000,"requires_kyc":false}',
        evaluator_sha3=p.evaluator_sha3, dataset_sha3=p.dataset_sha3,
        seed=p.seed, nonce=p.nonce, frozen_at=p.frozen_at,
        protocol_hash=p.protocol_hash, chain_index=p.chain_index)
    print(f"  Protocolo forjado verify(): {forged.verify()} (debe ser False)")
    print("=" * 78)
    return p


crypto = RealPQCryptoModule()
signer = crypto.generate_keypair()
chain = RealAuditChain(crypto=crypto, signer_keypair=signer)
_run(chain)
