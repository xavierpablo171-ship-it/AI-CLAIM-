# ==============================================================================
# AI-CLAIM — Celda 8/22
# MAPEO REGULATORIO: FS AI RMF v1.0 (230 control objectives OFICIALES)
# ==============================================================================
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class Status(str, Enum):
    DIRECT = "DIRECT"; PARTIAL = "PARTIAL"; SUPPORTING = "SUPPORTING"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"; NOT_MAPPED = "NOT_MAPPED"


@dataclass(frozen=True)
class ControlMapping:
    control_id: str
    framework: str
    framework_version: str
    control_text: str
    status: Status
    artifact_field: Optional[str]
    justification: str
    required_event_types: tuple = ()
    source_sheet: str = "View 1-Ctrl Obj Only"


FS_AI_RMF_OFFICIAL_COUNTS = {"GOVERN": 81, "MAP": 47, "MEASURE": 59, "MANAGE": 43}
FS_AI_RMF_TOTAL = sum(FS_AI_RMF_OFFICIAL_COUNTS.values())


SUPPORTING_CANDIDATES: List[ControlMapping] = [
    ControlMapping("GV-6.2.4", "FS AI RMF", "1.0",
        ("Monitoring and Early Warning Systems: The organization implements logging, "
         "monitoring, and early warning systems to detect potential failures, anomalies, "
         "or breaches in high-risk third-party AI systems."),
        Status.SUPPORTING, "audit_chain.entries[*].{timestamp,event_type,entry_hash}",
        ("La cadena de auditoría con timestamp y hash-chain puede servir como 'log "
         "repositories with timestamped records'; no implementa detección de anomalías."),
        required_event_types=("attested_evaluation",)),
    ControlMapping("MS-2.7.4", "FS AI RMF", "1.0",
        ("Security Metrics and Log Monitoring: The organization defines and tracks AI "
         "security and resilience metrics, ensuring alignment with existing frameworks."),
        Status.SUPPORTING, "audit_chain.entries[*]",
        "Puede alimentar un SIEM; no define ni calcula métricas de seguridad.",
        required_event_types=("attested_evaluation",)),
    ControlMapping("MS-2.1.3", "FS AI RMF", "1.0",
        ("Centralized TEVV Repository and Access: The organization maintains a centralized "
         "repository for TEVV documentation, promoting accessibility and version control."),
        Status.SUPPORTING, "audit_chain.entries (protocol_frozen + attested_evaluation)",
        "Actúa como log de version control; no es repositorio TEVV completo.",
        required_event_types=("protocol_frozen", "attested_evaluation")),
    ControlMapping("MP-4.2.1", "FS AI RMF", "1.0",
        ("Internal Controls for AI Components: The organization identifies and documents "
         "internal controls for AI system components, including third-party technologies."),
        Status.SUPPORTING, "frozen_protocol.rules_json + audit_chain",
        "Documenta un control específico de forma verificable; no es la matriz completa.",
        required_event_types=("protocol_frozen",)),
]


def coverage_report(sample_chain=None) -> Dict[str, object]:
    verified = []
    chain_event_types = set()
    if sample_chain is not None:
        chain_event_types = {e.event_type for e in sample_chain.entries}
    for c in SUPPORTING_CANDIDATES:
        confirmed = bool(c.required_event_types) and all(
            et in chain_event_types for et in c.required_event_types)
        verified.append((c.control_id, c.status.value, confirmed))
    return {
        "framework": "FS AI RMF v1.0",
        "total_control_objectives_oficiales": FS_AI_RMF_TOTAL,
        "distribucion_oficial": FS_AI_RMF_OFFICIAL_COUNTS,
        "candidatos_supporting": len(SUPPORTING_CANDIDATES),
        "candidatos_direct": 0,
        "detalle": verified,
        "nota": ("Ningún control es DIRECT. 'SUPPORTING' significa evidencia técnica "
                 "parcial; todos requieren además evidencia organizacional."),
    }


def _run():
    print("=" * 78)
    print("  MAPEO REGULATORIO — FS AI RMF v1.0 (230 control objectives)")
    print("=" * 78)
    print(f"\n  Total oficial: {FS_AI_RMF_TOTAL}")
    for func, n in FS_AI_RMF_OFFICIAL_COUNTS.items():
        print(f"    {func:10} : {n}")
    report = coverage_report()
    print(f"\n  SUPPORTING: {report['candidatos_supporting']} de {FS_AI_RMF_TOTAL}")
    print(f"  DIRECT    : {report['candidatos_direct']}\n")
    for c in SUPPORTING_CANDIDATES:
        print(f"  [{c.status.value}] {c.control_id} — {c.framework} v{c.framework_version}")
        print(f"      campo  : {c.artifact_field}")
        print(f"      límite : {c.justification[:110]}...\n")
    print("  Frase honesta:")
    print('  "AI-CLAIM aporta evidencia técnica verificable que respalda parcialmente')
    print('   4 de los 230 control objectives del FS AI RMF v1.0 (GV-6.2.4, MS-2.7.4,')
    print('   MS-2.1.3, MP-4.2.1). No sustituye los controles organizacionales."')
    print("\n" + "=" * 78)
    return report


_run()
