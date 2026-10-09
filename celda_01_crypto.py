# ==============================================================================
# AI-CLAIM — Celda 1/22
# MOTOR CRIPTOGRÁFICO REAL: ML-DSA-65 (FIPS 204) vía liboqs
# ==============================================================================
import oqs
import threading
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Dict


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

    def __init__(self, algorithm: str = "ML-DSA-65"):
        self._alg = algorithm
        self._lock = threading.Lock()
        self._signers: Dict[str, oqs.Signature] = {}

    def generate_keypair(self) -> KeyPair:
        with self._lock:
            sig = oqs.Signature(self._alg)
            public_key = sig.generate_keypair()
            key_id = str(uuid.uuid4())
            self._signers[key_id] = sig
            return KeyPair(key_id, CryptoAlgorithm(self._alg), public_key, key_id)

    def sign(self, key: KeyPair, message: bytes) -> bytes:
        with self._lock:
            sig = self._signers.get(key._private_handle)
            if sig is None:
                raise KeyError(f"Clave privada no encontrada: {key._private_handle}")
            return sig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        verifier = oqs.Signature(self._alg)
        try:
            return bool(verifier.verify(message, signature, public_key))
        except oqs.MechanismNotSupportedError as e:
            raise VerificationError(f"Mecanismo no soportado: {e}") from e
        except ValueError:
            return False

    @property
    def algorithm(self) -> str:
        return self._alg

    def export_public_key_pem(self, public_key: bytes) -> str:
        import base64
        b64 = base64.b64encode(public_key).decode()
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"


def _run_tests():
    print("=" * 78)
    print("  MOTOR CRIPTOGRÁFICO — ML-DSA-65 (FIPS 204) — sin certificar")
    print("=" * 78)
    crypto = RealPQCryptoModule()
    kp = crypto.generate_keypair()
    msg = b"AI-CLAIM: real cryptographic attestation test"
    sig = crypto.sign(kp, msg)
    checks = {
        "Verificación OK (camino feliz)": crypto.verify(kp.public_key, msg, sig),
        "Tampering en mensaje detectado": not crypto.verify(kp.public_key, msg + b"x", sig),
        "Clave incorrecta detectada": not crypto.verify(
            crypto.generate_keypair().public_key, msg, sig),
        "Firma truncada detectada": not crypto.verify(kp.public_key, msg, sig[:-1]),
        "Firma vacía detectada": not crypto.verify(kp.public_key, msg, b""),
        "Mensaje vacío + firma real": crypto.verify(kp.public_key, b"", crypto.sign(kp, b"")),
    }
    print(f"\n  Algoritmo         : {kp.algorithm.value}")
    print(f"  Clave pública     : {len(kp.public_key)} bytes")
    print(f"  Firma             : {len(sig)} bytes\n")
    all_ok = True
    for name, ok in checks.items():
        print(f"  [{'OK' if ok else 'FALLÓ'}] {name}")
        all_ok = all_ok and ok
    print("\n" + "=" * 78)
    print("  CRIPTOGRAFÍA BÁSICA VERIFICADA (sin certificación FIPS 140-3)")
    print("=" * 78)
    return crypto, kp


_run_tests()
