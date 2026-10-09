# ==============================================================================
# AI-CLAIM — Bundle portable + verificador (v5 — post Challenge #003)
# Cierra: version binding, NFC, taxonomía de errores, ataques #003.
# ==============================================================================
import copy
import hashlib
import json
import unicodedata
from enum import Enum
from typing import Any, Dict, List, Optional

_DOMAIN_PROTOCOL = b"AI-CLAIM/protocol/v1\x00"
_DOMAIN_RESULT = b"AI-CLAIM/eval-result/v1\x00"
_DOMAIN_ENTRY = b"AI-CLAIM/audit-entry/v1\x00"
SUPPORTED_BUNDLE_VERSIONS = {"4.0", "5.0"}


def _nfc(obj):
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {_nfc(k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_nfc(x) for x in obj]
    return obj


def _canon(obj) -> str:
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"), allow_nan=False)


class Status(str, Enum):
    VALID = "VALID"
    CONSISTENT = "CONSISTENT"
    INVALID = "INVALID"
    INCONCLUSIVE = "INCONCLUSIVE"
    MALFORMED = "MALFORMED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"


class BundleVerificationReport:
    def __init__(self) -> None:
        self.checks: Dict[str, Optional[bool]] = {}
        self.failures: List[str] = []
        self.malformed_reason: Optional[str] = None
        self.unsupported_version: Optional[str] = None
        self.identity_confirmed: bool = False
        self.anchor_declared_unverified: bool = False

    def check(self, name: str, condition: Optional[bool]) -> None:
        if name in self.checks:
            raise AssertionError(f"Chequeo duplicado: {name}")
        self.checks[name] = condition
        if condition is False:
            self.failures.append(name)

    @property
    def status(self) -> Status:
        if self.unsupported_version is not None:
            return Status.UNSUPPORTED_VERSION
        if self.malformed_reason is not None:
            return Status.MALFORMED
        if any(v is False for v in self.checks.values()):
            return Status.INVALID
        if any(v is None for v in self.checks.values()):
            return Status.INCONCLUSIVE
        if len(self.checks) == 0:
            return Status.MALFORMED
        return Status.VALID if self.identity_confirmed else Status.CONSISTENT

    @property
    def error_code(self) -> Optional[str]:
        if self.unsupported_version is not None:
            return "UNSUPPORTED_BUNDLE_VERSION"
        if self.malformed_reason is not None:
            return "MALFORMED_BUNDLE"
        for check_name, code in [
            ("binding:bundle_version_matches_signed", "VERSION_DOWNGRADE_OR_MISMATCH"),
            ("binding:entry_references_result",       "ENTRY_RESULT_BINDING_BROKEN"),
            ("binding:entry_references_protocol",     "ENTRY_PROTOCOL_BINDING_BROKEN"),
            ("binding:result_references_protocol",    "RESULT_PROTOCOL_BINDING_BROKEN"),
            ("protocol_hash_recomputed",              "PROTOCOL_HASH_MISMATCH"),
            ("result_hash_recomputed",                "RESULT_HASH_MISMATCH"),
            ("entry_hash_recomputed",                 "ENTRY_HASH_MISMATCH"),
            ("signature_valid_ml_dsa_65",             "SIGNATURE_INVALID"),
            ("trust_anchor:key_matches_pinned",       "UNTRUSTED_KEY"),
        ]:
            if self.checks.get(check_name) is False:
                return code
        return None

    @property
    def valid(self) -> bool:
        return self.status == Status.VALID

    def summary(self) -> Dict[str, Any]:
        return {"status": self.status.value, "error_code": self.error_code,
                "total_checks": len(self.checks), "failures": list(self.failures),
                "unverifiable": [k for k, v in self.checks.items() if v is None],
                "malformed_reason": self.malformed_reason,
                "unsupported_version": self.unsupported_version,
                "anchor_declared_but_not_independently_verified": self.anchor_declared_unverified}


def to_bundle(protocol, result, attestation, chain, signer_public_key: bytes,
              anchor_tx_signature: Optional[str] = None) -> dict:
    entry = chain.entries[attestation.chain_index]
    signed_version = entry.payload.get("bundle_schema_version")
    if signed_version is None:
        raise ValueError(
            "entry.payload no contiene bundle_schema_version — "
            "bundle creado con código pre-fix, no se puede emitir como v4.0")
    bundle = {
        "ai_claim_bundle_version": signed_version,
        "protocol": {
            "protocol_id": protocol.protocol_id, "version": protocol.version,
            "rules_json": protocol.rules_json, "evaluator_sha3": protocol.evaluator_sha3,
            "dataset_sha3": protocol.dataset_sha3, "seed": protocol.seed,
            "nonce": protocol.nonce, "protocol_hash": protocol.protocol_hash,
        },
        "result": {
            "protocol_hash": result.protocol_hash, "input_hash": result.input_hash,
            "decision": result.decision, "score": result.score,
            "reasons": list(result.reasons), "result_hash": result.result_hash,
        },
        "chain_entry": {
            "index": entry.index, "timestamp": entry.timestamp, "event_type": entry.event_type,
            "payload": entry.payload, "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash, "signature": entry.signature,
        },
        "signer_public_key_hex": signer_public_key.hex(),
        "external_anchor": None,
    }
    if anchor_tx_signature is not None:
        bundle["external_anchor"] = {
            "type": "solana-memo", "anchors": "entry_hash",
            "entry_hash_anchored": entry.entry_hash, "tx_signature": anchor_tx_signature,
        }
    return bundle


def _require(d: dict, key: str):
    if key not in d:
        raise KeyError(f"falta el campo requerido: {key}")
    return d[key]


def verify_bundle_standalone(bundle: dict,
                              trusted_public_key_hex: Optional[str] = None) -> BundleVerificationReport:
    report = BundleVerificationReport()
    version = bundle.get("ai_claim_bundle_version")
    if version not in SUPPORTED_BUNDLE_VERSIONS:
        report.unsupported_version = str(version)
        return report
    try:
        required = ["protocol", "result", "chain_entry", "signer_public_key_hex"]
        for name in required:
            report.check(f"bundle_has:{name}", name in bundle and bundle[name] is not None)
        if not all(bundle.get(n) is not None for n in required):
            return report

        p = _require(bundle, "protocol")
        p_body = {k: _require(p, k) for k in
                  ("protocol_id", "version", "rules_json", "evaluator_sha3",
                   "dataset_sha3", "seed", "nonce")}
        recomputed_protocol_hash = hashlib.sha3_512(_DOMAIN_PROTOCOL + _canon(p_body).encode()).hexdigest()
        report.check("protocol_hash_recomputed", recomputed_protocol_hash == p.get("protocol_hash"))

        r = _require(bundle, "result")
        r_body = {k: _require(r, k) for k in
                  ("protocol_hash", "input_hash", "decision", "score", "reasons")}
        recomputed_result_hash = hashlib.sha3_512(_DOMAIN_RESULT + _canon(r_body).encode()).hexdigest()
        report.check("result_hash_recomputed", recomputed_result_hash == r.get("result_hash"))
        report.check("binding:result_references_protocol", r.get("protocol_hash") == p.get("protocol_hash"))

        e = _require(bundle, "chain_entry")
        e_body = {k: _require(e, k) for k in ("index", "timestamp", "event_type", "payload", "prev_hash")}
        e_canonical = _DOMAIN_ENTRY + _canon(e_body).encode()
        recomputed_entry_hash = hashlib.sha3_512(e_canonical).hexdigest()
        report.check("entry_hash_recomputed", recomputed_entry_hash == e.get("entry_hash"))
        report.check("binding:entry_references_result",
                      e.get("payload", {}).get("result_hash") == r.get("result_hash"))
        report.check("binding:entry_references_protocol",
                      e.get("payload", {}).get("protocol_hash") == p.get("protocol_hash"))

        declared_version = bundle.get("ai_claim_bundle_version")
        signed_version = e.get("payload", {}).get("bundle_schema_version")
        report.check(
            "binding:bundle_version_matches_signed",
            declared_version is not None and signed_version is not None
            and declared_version == signed_version)

        bundle_pubkey_hex = _require(bundle, "signer_public_key_hex")
        if trusted_public_key_hex is not None:
            match = (bundle_pubkey_hex == trusted_public_key_hex)
            report.check("trust_anchor:key_matches_pinned", match)
            report.identity_confirmed = match

        try:
            import oqs
            verifier = oqs.Signature("ML-DSA-65")
            pubkey = bytes.fromhex(bundle_pubkey_hex)
            signature = bytes.fromhex(_require(e, "signature"))
            report.check("signature_valid_ml_dsa_65", bool(verifier.verify(e_canonical, signature, pubkey)))
        except ModuleNotFoundError:
            report.check("signature_valid_ml_dsa_65", None)

        anchor = bundle.get("external_anchor")
        if anchor is not None:
            report.check("external_anchor:declared_covers_entry", anchor.get("anchors") == "entry_hash")
            report.check("external_anchor:declared_matches_entry",
                          anchor.get("entry_hash_anchored") == e.get("entry_hash"))
            report.anchor_declared_unverified = True

    except Exception as exc:
        report.malformed_reason = f"{type(exc).__name__}: {exc}"

    return report


def _mutate(bundle: dict, *path, value) -> dict:
    b = copy.deepcopy(bundle)
    target = b
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return b


def run_adversarial_suite(clean_bundle: dict, signer_public_key_hex: str) -> list:
    results = []

    def record(name, expected_status, bundle, **kwargs):
        r = verify_bundle_standalone(bundle, **kwargs)
        ok = (r.status.value == expected_status)
        results.append((name, ok, r.status.value, r.error_code))
        return r

    record("clean_bundle_VALID", "VALID", clean_bundle,
           trusted_public_key_hex=signer_public_key_hex)
    record("clean_bundle_without_pin_is_CONSISTENT_not_VALID", "CONSISTENT", clean_bundle)

    record("mutated_protocol_rules", "INVALID",
           _mutate(clean_bundle, "protocol", "rules_json", value='{"tampered":true}'))
    record("mutated_result_decision", "INVALID",
           _mutate(clean_bundle, "result", "decision",
                    value=not clean_bundle["result"]["decision"]))
    record("mutated_entry_payload_directly", "INVALID",
           _mutate(clean_bundle, "chain_entry", "payload", "decision",
                    value=not clean_bundle["chain_entry"]["payload"]["decision"]))
    sig = bytearray(bytes.fromhex(clean_bundle["chain_entry"]["signature"]))
    sig[0] ^= 0xFF
    record("tampered_signature_byte", "INVALID",
           _mutate(clean_bundle, "chain_entry", "signature", value=bytes(sig).hex()))
    record("result_references_wrong_protocol", "INVALID",
           _mutate(clean_bundle, "result", "protocol_hash", value="f" * 128))
    record("entry_references_wrong_result_hash", "INVALID",
           _mutate(clean_bundle, "chain_entry", "payload", "result_hash", value="f" * 128))

    import builtins
    real_import = builtins.__import__
    def blocked_import(name, *a, **k):
        if name == "oqs":
            raise ModuleNotFoundError("simulado")
        return real_import(name, *a, **k)
    attacked = _mutate(clean_bundle, "result", "decision",
                        value=not clean_bundle["result"]["decision"])
    r_body = {k: attacked["result"][k] for k in
              ("protocol_hash", "input_hash", "decision", "score", "reasons")}
    attacked["result"]["result_hash"] = hashlib.sha3_512(
        _DOMAIN_RESULT + _canon(r_body).encode()).hexdigest()
    attacked["chain_entry"]["payload"]["result_hash"] = attacked["result"]["result_hash"]
    e_body = {k: attacked["chain_entry"][k] for k in
              ("index", "timestamp", "event_type", "payload", "prev_hash")}
    attacked["chain_entry"]["entry_hash"] = hashlib.sha3_512(
        _DOMAIN_ENTRY + _canon(e_body).encode()).hexdigest()
    if attacked.get("external_anchor"):
        attacked["external_anchor"]["entry_hash_anchored"] = attacked["chain_entry"]["entry_hash"]
    builtins.__import__ = blocked_import
    record("Challenge001_BREAK1_no_liboqs_never_VALID", "INCONCLUSIVE", attacked)
    builtins.__import__ = real_import

    record("Challenge001_BREAK2_untrusted_key_rejected", "INVALID", clean_bundle,
           trusted_public_key_hex="ab" * (len(signer_public_key_hex) // 2))

    malformed = copy.deepcopy(clean_bundle)
    malformed["signer_public_key_hex"] = "ESTO-NO-ES-HEX-VALIDO"
    record("Challenge001_BREAK4_malformed_no_crash", "MALFORMED", malformed)

    record("Challenge002_unsupported_bundle_version", "UNSUPPORTED_VERSION",
           _mutate(clean_bundle, "ai_claim_bundle_version", value="999.999"))

    anchored = copy.deepcopy(clean_bundle)
    anchored["external_anchor"] = {"type": "solana-memo", "anchors": "entry_hash",
                                     "entry_hash_anchored": anchored["chain_entry"]["entry_hash"],
                                     "tx_signature": "tx-inventada-no-verificada"}
    r_anchor = verify_bundle_standalone(anchored, trusted_public_key_hex=signer_public_key_hex)
    ok_anchor = (r_anchor.status.value == "VALID" and r_anchor.anchor_declared_unverified is True)
    results.append(("Challenge002_anchor_declared_flagged_unverified", ok_anchor,
                     f"{r_anchor.status.value} (anchor_unverified={r_anchor.anchor_declared_unverified})",
                     r_anchor.error_code))

    record("Challenge003_bundle_version_downgrade_to_supported", "INVALID",
           _mutate(clean_bundle, "ai_claim_bundle_version", value="3.0"))
    record("Challenge003_bundle_version_upgrade_to_supported", "INVALID",
           _mutate(clean_bundle, "ai_claim_bundle_version", value="5.0"))

    return results


def print_adversarial_results(results):
    print("\n" + "=" * 78)
    print("  BATERÍA DE ATAQUES (Challenge #001 + #002 + #003)")
    print("=" * 78)
    all_ok = True
    for item in results:
        name, ok, status = item[0], item[1], item[2]
        err = item[3] if len(item) > 3 else None
        err_str = f" [{err}]" if err else ""
        print(f"  [{'OK' if ok else 'FALLÓ'}] {name:52} {status}{err_str}")
        all_ok = all_ok and ok
    print(f"\n  TODOS LOS ATAQUES SE COMPORTARON COMO SE ESPERABA: {all_ok}")
    print("=" * 78)
    return all_ok
