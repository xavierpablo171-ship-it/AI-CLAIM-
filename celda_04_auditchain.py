# ==============================================================================
# AI-CLAIM — Celda 4/22 (fix NFC aplicado)
# CADENA DE AUDITORÍA: hash-chained + firmas ML-DSA-65
# ==============================================================================
import copy, hashlib, json, threading, time, unicodedata
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 128
_DOMAIN_ENTRY = b"AI-CLAIM/audit-entry/v1\x00"


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

    def export(self):
        return [asdict(e) for e in self._entries]

    @property
    def entries(self):
        return tuple(self._entries)

    @property
    def head(self):
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH


def _run(crypto, signer):
    print("=" * 78)
    print("  CADENA DE AUDITORÍA")
    print("=" * 78)
    chain = RealAuditChain(crypto=crypto, signer_keypair=signer)
    for i in range(5):
        chain.append("test_event", {"i": i, "data": f"entry-{i}"})
    valid, _ = chain.verify_chain()
    print(f"  Entradas: {len(chain.entries)} | Cadena+firmas válida: {valid}")
    original = chain.entries[2].payload["data"]
    chain.entries[2].payload["data"] = "TAMPERED"
    v, b = chain.verify_chain()
    print(f"  Mutación: válida={v}, rota en {b}")
    chain.entries[2].payload["data"] = original
    e = chain.entries[2]
    e.payload["data"] = "TAMPERED_REHASHED"
    e.entry_hash = e.compute_hash()
    v, b = chain.verify_chain()
    print(f"  Rehash-forward: válida={v}, rota en {b}")
    e.payload["data"] = original; e.entry_hash = e.compute_hash()
    print(f"  Head correcto: {chain.verify_chain(expected_head=chain.head)[0]}")
    print(f"  Head falso:    {chain.verify_chain(expected_head='0'*128)[0]}")
    print("=" * 78)
    return chain


crypto = RealPQCryptoModule()
signer = crypto.generate_keypair()
_run(crypto, signer)
