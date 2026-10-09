# ==============================================================================
# AI-CLAIM — Celda 18c/22
# MÓDULOS DEL PAQUETE: regulatory.py, __init__.py, cli.py
# ==============================================================================
import pathlib

SRC = pathlib.Path("ai_claim_real_pkg/src/ai_claim_real")

regulatory_py = '''"""Mapeo honesto contra el FS AI RMF v1.0 OFICIAL (230 control objectives,
GOVERN=81 MAP=47 MEASURE=59 MANAGE=43). AI-CLAIM aporta evidencia SUPPORTING
parcial a un numero acotado; nunca DIRECT."""
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class Status(str, Enum):
    DIRECT = "DIRECT"
    PARTIAL = "PARTIAL"
    SUPPORTING = "SUPPORTING"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NOT_MAPPED = "NOT_MAPPED"


@dataclass(frozen=True)
class ControlMapping:
    control_id: str
    framework: str
    framework_version: str
    control_text: str
    status: Status
    artifact_field: Optional[str]
    justification: str


FS_AI_RMF_OFFICIAL_COUNTS = {"GOVERN": 81, "MAP": 47, "MEASURE": 59, "MANAGE": 43}
FS_AI_RMF_TOTAL = sum(FS_AI_RMF_OFFICIAL_COUNTS.values())

SUPPORTING_CANDIDATES: List[ControlMapping] = [
    ControlMapping("GV-6.2.4", "FS AI RMF", "1.0",
        "Monitoring and Early Warning Systems (logging/monitoring de terceros de alto riesgo)",
        Status.SUPPORTING, "audit_chain.entries[*].{timestamp,event_type,entry_hash}",
        "Log con timestamp y hash-chain sirve como evidencia de 'log repositories with "
        "timestamped records'; no implementa deteccion de anomalias por si solo."),
    ControlMapping("MS-2.7.4", "FS AI RMF", "1.0",
        "Security Metrics and Log Monitoring",
        Status.SUPPORTING, "audit_chain.entries[*]",
        "Puede alimentar un SIEM; no define ni calcula metricas de seguridad."),
    ControlMapping("MS-2.1.3", "FS AI RMF", "1.0",
        "Centralized TEVV Repository and Access (version control)",
        Status.SUPPORTING, "audit_chain.entries (protocol_frozen + attested_evaluation)",
        "Actua como log de version control de evaluaciones; no es un repositorio TEVV completo."),
    ControlMapping("MP-4.2.1", "FS AI RMF", "1.0",
        "Internal Controls for AI Components",
        Status.SUPPORTING, "frozen_protocol.rules_json + audit_chain",
        "El protocolo congelado documenta un control verificable; no es la matriz de "
        "control interno completa que pide el objetivo."),
]


def coverage_report(sample_chain=None) -> dict:
    verified = [(c.control_id, c.status.value,
                 sample_chain is not None and len(sample_chain.entries) > 0)
                for c in SUPPORTING_CANDIDATES]
    return {
        "framework": "FS AI RMF v1.0",
        "total_control_objectives_oficiales": FS_AI_RMF_TOTAL,
        "distribucion_oficial": FS_AI_RMF_OFFICIAL_COUNTS,
        "candidatos_supporting": len(SUPPORTING_CANDIDATES),
        "candidatos_direct": 0,
        "detalle": verified,
        "nota": ("Ningun control es DIRECT. AI-CLAIM no sustituye los controles "
                 "organizacionales, de gobernanza ni de revision humana del framework."),
    }
'''
(SRC / "regulatory.py").write_text(regulatory_py)


init_py = '''"""AI-CLAIM — ML-DSA-65 (FIPS 204), sin certificar FIPS 140-3."""
from .crypto import CryptoAlgorithm, KeyPair, RealPQCryptoModule, VerificationError
from .audit import AuditEntry, GENESIS_HASH, RealAuditChain
from .protocol import FrozenProtocol, verify_protocol_registered
from .engines import (Attestation, AttestationEngine, AIClaimPipeline,
                       EvaluationEngine, EvaluationResult, verify_attestation)
from .safr import (AgentCredential, Permit, RealSAFRGuard,
                    issue_credential, verify_credential)
from .regulatory import ControlMapping, Status, coverage_report, SUPPORTING_CANDIDATES

__version__ = "0.1.0"

__all__ = [
    "CryptoAlgorithm", "KeyPair", "RealPQCryptoModule", "VerificationError",
    "AuditEntry", "GENESIS_HASH", "RealAuditChain",
    "FrozenProtocol", "verify_protocol_registered",
    "Attestation", "AttestationEngine", "AIClaimPipeline",
    "EvaluationEngine", "EvaluationResult", "verify_attestation",
    "AgentCredential", "Permit", "RealSAFRGuard", "issue_credential", "verify_credential",
    "ControlMapping", "Status", "coverage_report", "SUPPORTING_CANDIDATES",
]
'''
(SRC / "__init__.py").write_text(init_py)


cli_py = '''"""CLI del paquete. Reporta estado real, no cifras fijas."""
import sys
import hashlib
from . import (__version__, RealPQCryptoModule, RealAuditChain, coverage_report)
from .engines import EvaluationEngine, AttestationEngine, AIClaimPipeline
from .safr import RealSAFRGuard, issue_credential


def cmd_verify(args):
    crypto = RealPQCryptoModule()
    signer = crypto.generate_keypair()
    issuer = crypto.generate_keypair()
    chain = RealAuditChain(crypto, signer)
    pipeline = AIClaimPipeline(EvaluationEngine(), AttestationEngine(chain, crypto, signer))
    pipeline.register_protocol(
        chain, "safr-cli-v1", "1.0",
        {"policies": {"cli-agent": {"credit_decision": 5_000_000}},
         "requires_kyc": False, "currency": "USD"},
        evaluator_sha3=hashlib.sha3_512(b"cli").hexdigest(),
        dataset_sha3=hashlib.sha3_512(b"n/a").hexdigest(), seed=1)
    guard = RealSAFRGuard(pipeline, crypto, issuer.public_key, protocol_id="safr-cli-v1")
    cred = issue_credential(crypto, issuer, "cli-agent", "model", "1.0",
                             ["credit_decision"], {"credit_decision": 5_000_000}, "USD")
    for amt in [2_500_000, 7_500_000]:
        permit, reason = guard.authorize(cred, "credit_decision", amt, "USD", "c")
        print(f"  amount_cents={amt:>10} -> permit={permit is not None} ({reason})")
    valid, _ = chain.verify_chain()
    print(f"  Chain valid: {valid}")
    print(f"  Entries: {len(chain.entries)}")
    return 0 if valid else 1


def cmd_mapper(args):
    r = coverage_report()
    print(f"  Total oficial FS AI RMF v1.0: {r['total_control_objectives_oficiales']}")
    print(f"  Candidatos SUPPORTING       : {r['candidatos_supporting']}")
    print(f"  Candidatos DIRECT           : {r['candidatos_direct']}")
    print(f"  {r['nota']}")
    return 0


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="ai-claim-real")
    parser.add_argument("--version", action="version", version=f"ai-claim-real {__version__}")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("verify"); p.set_defaults(func=cmd_verify)
    p2 = sub.add_parser("mapper"); p2.set_defaults(func=cmd_mapper)
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
'''
(SRC / "cli.py").write_text(cli_py)

print("[OK] Celda 18c — regulatory.py, __init__.py, cli.py")
