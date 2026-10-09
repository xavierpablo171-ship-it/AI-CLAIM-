# ==============================================================================
# AI-CLAIM — Celda 18a/22 (fix NFC aplicado)
# MÓDULOS DEL PAQUETE: crypto.py, audit.py, protocol.py
# ==============================================================================
import pathlib

SRC = pathlib.Path("ai_claim_real_pkg/src/ai_claim_real")
SRC.mkdir(parents=True, exist_ok=True)

crypto_py = '''"""Crypto ML-DSA-65 (FIPS 204) via liboqs. Sin certificacion FIPS 140-3."""
import threading, uuid
from dataclasses import dataclass
from enum import Enum
from typing import Dict
import oqs


class CryptoAlgorithm(str, Enum):
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


class VerificationError(Exception):
    pass


@dataclass
class KeyPair:
    key_id: str
    algorithm: CryptoAlgorithm
    public_key: bytes
    _private_handle: str


class RealPQCryptoModule:
    MODULE_ID = "ai-claim-crypto-real-v1"

    def __init__(self, algorithm="ML-DSA-65"):
        self._alg = algorithm
        self._lock = threading.Lock()
        self._signers: Dict[str, "oqs.Signature"] = {}

    def generate_keypair(self) -> KeyPair:
        with self._lock:
            sig = oqs.Signature(self._alg)
            public_key = sig.generate_keypair()
            key_id = str(uuid.uuid4())
            self._signers[key_id] = sig
            return KeyPair(key_id, CryptoAlgorithm(self._alg), public_key, key_id)

    def sign(self, key, message):
        with self._lock:
            sig = self._signers.get(key._private_handle)
            if sig is None:
                raise KeyError(f"clave privada no encontrada: {key._private_handle}")
            return sig.sign(message)

    def verify(self, public_key, message, signature):
        verifier = oqs.Signature(self._alg)
        try:
            return bool(verifier.verify(message, signature, public_key))
        except oqs.MechanismNotSupportedError as e:
            raise VerificationError(f"mecanismo no soportado: {e}") from e
        except ValueError:
            return False

    @property
    def algorithm(self):
        return self._alg
'''
(SRC / "crypto.py").write_text(crypto_py)


audit_py = '''"""Cadena de auditoria hash-chained + firmada con NFC."""
import copy, hashlib, json, threading, time, unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 128
_DOMAIN_ENTRY = b"AI-CLAIM/audit-entry/v1\\x00"


def _nfc(obj):
    if isinstance(obj, str): return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict): return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)): return [_nfc(x) for x in obj]
    return obj


def _canon_bytes_entry(obj) -> bytes:
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    event_type: str
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""
    signature: str = ""

    def canonical(self) -> bytes:
        body = {"index": self.index, "timestamp": self.timestamp,
                "event_type": self.event_type, "payload": self.payload,
                "prev_hash": self.prev_hash}
        return _DOMAIN_ENTRY + _canon_bytes_entry(body)

    def compute_hash(self) -> str:
        return hashlib.sha3_512(self.canonical()).hexdigest()


class RealAuditChain:
    def __init__(self, crypto, signer_keypair):
        self._crypto = crypto
        self._signer = signer_keypair
        self._entries: List[AuditEntry] = []
        self._lock = threading.Lock()

    def append(self, event_type, payload):
        with self._lock:
            prev = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            entry = AuditEntry(len(self._entries), time.time(), event_type,
                                copy.deepcopy(payload), prev)
            entry.entry_hash = entry.compute_hash()
            entry.signature = self._crypto.sign(self._signer, entry.canonical()).hex()
            self._entries.append(entry)
            return entry

    def verify_signature(self, entry):
        return self._crypto.verify(self._signer.public_key, entry.canonical(),
                                    bytes.fromhex(entry.signature))

    def verify_chain(self, expected_head=None):
        prev = GENESIS_HASH
        for i, e in enumerate(self._entries):
            if e.index != i or e.prev_hash != prev: return False, i
            if e.compute_hash() != e.entry_hash: return False, i
            if not self.verify_signature(e): return False, i
            prev = e.entry_hash
        if expected_head is not None and prev != expected_head:
            return False, len(self._entries)
        return True, None

    @property
    def entries(self):
        return tuple(self._entries)

    @property
    def head(self):
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH
'''
(SRC / "audit.py").write_text(audit_py)


protocol_py = '''"""Protocolo congelado: inmutable, atado a evaluador+dataset+semilla + NFC."""
import hashlib, json, secrets, time, unicodedata
from dataclasses import dataclass

_DOMAIN_PROTOCOL = b"AI-CLAIM/protocol/v1\\x00"


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

    def verify(self):
        body = {"protocol_id": self.protocol_id, "version": self.version,
                "rules_json": self.rules_json, "evaluator_sha3": self.evaluator_sha3,
                "dataset_sha3": self.dataset_sha3, "seed": self.seed, "nonce": self.nonce}
        return _hash_body(body) == self.protocol_hash

    @classmethod
    def freeze(cls, chain, protocol_id, version, rules, evaluator_sha3, dataset_sha3, seed):
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


def verify_protocol_registered(protocol, chain):
    if not protocol.verify() or protocol.chain_index >= len(chain.entries):
        return False
    entry = chain.entries[protocol.chain_index]
    return (entry.event_type == "protocol_frozen"
            and entry.payload.get("protocol_hash") == protocol.protocol_hash
            and chain.verify_signature(entry))
'''
(SRC / "protocol.py").write_text(protocol_py)

print("[OK] Celda 18a — crypto.py, audit.py, protocol.py (fix NFC)")
