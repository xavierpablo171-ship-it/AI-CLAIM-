# ==============================================================================
# AI-CLAIM — Celda 2/22
# CROSS-VERIFICATION real: liboqs vs. OpenSSL
# ==============================================================================
import subprocess, tempfile, os, hashlib, json, base64
from datetime import datetime, timezone

ML_DSA_65_OID_DER = bytes.fromhex("060b6086480186fa6b5008010012")


def build_spki_der(public_key: bytes, oid_der: bytes) -> bytes:
    def _len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b
    alg_id = bytes([0x30]) + _len(len(oid_der)) + oid_der
    bs_body = b"\x00" + public_key
    bs = bytes([0x03]) + _len(len(bs_body)) + bs_body
    body = alg_id + bs
    return bytes([0x30]) + _len(len(body)) + body


def der_to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def openssl_supports_ml_dsa() -> tuple:
    v = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    version_str = v.stdout.strip()
    a = subprocess.run("openssl list -signature-algorithms 2>/dev/null | grep -i mldsa",
                        shell=True, capture_output=True, text=True)
    return version_str, bool(a.stdout.strip())


def cross_verify_openssl(message, signature, public_key) -> dict:
    version_str, ml_dsa_native = openssl_supports_ml_dsa()
    result = {"openssl_version": version_str, "openssl_ml_dsa_supported": ml_dsa_native,
        "message_hex": message.hex(), "signature_hex": signature.hex(),
        "public_key_hex": public_key.hex(),
        "message_sha3_512": hashlib.sha3_512(message).hexdigest(),
        "signature_sha3_512": hashlib.sha3_512(signature).hexdigest(),
        "public_key_sha3_512": hashlib.sha3_512(public_key).hexdigest(),
        "attempted": False, "verification_result": None,
        "stdout": "", "stderr": "", "return_code": None, "skip_reason": None}
    if not ml_dsa_native:
        result["skip_reason"] = (
            f"OpenSSL instalado ({version_str}) no soporta ML-DSA de forma nativa "
            "(se requiere OpenSSL >= 3.5). Verificación cruzada NO disponible "
            "en este entorno; solo se reporta la verificación con liboqs.")
        return result
    result["attempted"] = True
    with tempfile.TemporaryDirectory() as tmpdir:
        msg_path = os.path.join(tmpdir, "message.bin")
        sig_path = os.path.join(tmpdir, "signature.bin")
        pub_path = os.path.join(tmpdir, "public.pem")
        with open(msg_path, "wb") as f: f.write(message)
        with open(sig_path, "wb") as f: f.write(signature)
        with open(pub_path, "w") as f:
            f.write(der_to_pem(build_spki_der(public_key, ML_DSA_65_OID_DER)))
        try:
            r = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-in", msg_path,
                 "-pubin", "-inkey", pub_path, "-sigfile", sig_path],
                capture_output=True, text=True, timeout=10)
            result["stdout"] = r.stdout; result["stderr"] = r.stderr
            result["return_code"] = r.returncode
            result["verification_result"] = (r.returncode == 0)
        except Exception as e:
            result["stderr"] = str(e); result["verification_result"] = False
    return result


def save_cross_verification_report(report, path="OPENSSL_VERIFICATION.json"):
    report["timestamp"] = datetime.now(timezone.utc).isoformat()
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["report_sha3_512"] = hashlib.sha3_512(canonical).hexdigest()
    with open(path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    return path


def _run(crypto, kp):
    print("=" * 78)
    print("  CROSS-VERIFICATION liboqs <-> OpenSSL")
    print("=" * 78)
    message = b"AI-CLAIM: cross-verification test"
    signature = crypto.sign(kp, message)
    liboqs_ok = crypto.verify(kp.public_key, message, signature)
    report = cross_verify_openssl(message, signature, kp.public_key)
    print(f"\n  OpenSSL version         : {report['openssl_version']}")
    print(f"  ML-DSA nativo en OpenSSL: {report['openssl_ml_dsa_supported']}")
    print(f"  Verificación liboqs     : {liboqs_ok}")
    if report["skip_reason"]:
        print(f"  Verificación OpenSSL    : NO INTENTADA — {report['skip_reason']}")
    else:
        print(f"  Verificación OpenSSL    : {report['verification_result']}")
    path = save_cross_verification_report(report, "OPENSSL_VERIFICATION.json")
    print(f"\n  Reporte guardado : {path}")
    if report["skip_reason"] is not None:
        status = "PARCIAL — solo verificado con liboqs, OpenSSL no disponible aquí"
    elif liboqs_ok and report["verification_result"]:
        status = "Cross-verification real: ambas implementaciones concuerdan"
    else:
        status = "DISCREPANCIA — revisar"
    print(f"\n  {status}")
    print("=" * 78)
    return report


crypto = RealPQCryptoModule()
kp = crypto.generate_keypair()
_run(crypto, kp)
