# ==============================================================================
# AI-CLAIM — Celda 12/22
# INFORME EJECUTIVO HTML
# ==============================================================================
from datetime import datetime, timezone
from typing import Dict


def _openssl_badge_html(xv):
    if xv.get("skip_reason"):
        return '<span class="badge warn">OpenSSL no disponible en este entorno</span>'
    if xv.get("verification_result") is True:
        return '<span class="badge ok">Verificado con OpenSSL</span>'
    return '<span class="badge warn">Verificación OpenSSL: discrepancia</span>'


def generate_real_executive_report(crypto_bench, append_bench, verify_chain_bench,
                                    coverage, cross_verify_report,
                                    output_path="ai_claim_real_report.html"):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    openssl_badge = _openssl_badge_html(cross_verify_report)
    h = []
    h.append('<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">')
    h.append('<title>AI-CLAIM - Informe Ejecutivo</title><style>')
    h.append('*{box-sizing:border-box}body{margin:0;padding:32px;font-family:-apple-system,sans-serif;'
              'background:#0f1419;color:#e6edf3;line-height:1.55}.container{max-width:1100px;margin:0 auto}')
    h.append('header{border-bottom:2px solid #2f81f7;padding-bottom:20px;margin-bottom:32px}'
              'h1{margin:0 0 8px 0;font-size:32px}.subtitle{color:#8b949e;font-size:15px}')
    h.append('.badge{display:inline-block;padding:4px 12px;border-radius:12px;background:#2f81f7;'
              'color:#fff;font-size:12px;font-weight:600;margin-right:8px}'
              '.badge.ok{background:#3fb950}.badge.warn{background:#d29922}.badge.real{background:#a371f7}')
    h.append('h2{font-size:22px;margin:40px 0 16px 0;border-left:4px solid #2f81f7;padding-left:14px}'
              '.card{background:#1a2028;border:1px solid #2a3441;border-radius:10px;padding:24px;margin-bottom:20px}')
    h.append('table{width:100%;border-collapse:collapse;font-size:14px}'
              'th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #2a3441}'
              'th{color:#8b949e;font-weight:600;text-transform:uppercase;font-size:11px}'
              'td.num{text-align:right;font-family:monospace}')
    h.append('.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:20px 0}'
              '.stat{background:#1a2028;border:1px solid #2a3441;border-radius:10px;padding:20px}'
              '.stat .label{color:#8b949e;font-size:12px;text-transform:uppercase}'
              '.stat .value{font-size:28px;font-weight:700;margin:8px 0 4px 0;font-family:monospace;color:#2f81f7}'
              '.stat .unit{color:#8b949e;font-size:13px}')
    h.append('.note{background:rgba(47,129,247,0.08);border-left:3px solid #2f81f7;padding:12px 16px;'
              'border-radius:6px;margin:16px 0}.note.warn{background:rgba(210,153,34,0.10);border-left-color:#d29922}')
    h.append('.footer{margin-top:48px;padding-top:20px;border-top:1px solid #2a3441;color:#8b949e;'
              'font-size:12px;text-align:center}</style></head><body><div class="container">')

    h.append('<header><h1>AI-CLAIM</h1>')
    h.append('<div class="subtitle">Capa de atestación criptográfica con ML-DSA-65 (FIPS 204), sin certificar</div>')
    h.append(f'<div style="margin-top:12px"><span class="badge real">Criptografía ML-DSA-65 real</span>'
              f'{openssl_badge}<span class="badge">Confidencial</span></div>')
    h.append(f'<div class="subtitle" style="margin-top:8px">Generado: {now}</div></header>')

    h.append('<h2>1. Resumen Ejecutivo</h2><div class="card">')
    h.append('<p>AI-CLAIM firma con <strong>ML-DSA-65 (FIPS 204)</strong> vía liboqs. '
             'No está certificado FIPS 140-3.</p><div class="grid">')
    h.append(f'<div class="stat"><div class="label">Firma p50</div>'
              f'<div class="value">{crypto_bench["sign_ms"]["p50"]:.2f}</div><div class="unit">ms</div></div>')
    h.append(f'<div class="stat"><div class="label">Firma p999 (n={crypto_bench["sign_ms"]["n"]})</div>'
              f'<div class="value">{crypto_bench["sign_ms"]["p999"]:.2f}</div><div class="unit">ms</div></div>')
    entries_n = list(verify_chain_bench.values())[0]["actual_chain_length"] if verify_chain_bench else 0
    verify_ms = list(verify_chain_bench.values())[0]["elapsed_ms"] if verify_chain_bench else 0
    h.append(f'<div class="stat"><div class="label">verify_chain ({entries_n} entradas)</div>'
              f'<div class="value">{verify_ms:.1f}</div><div class="unit">ms</div></div>')
    h.append(f'<div class="stat"><div class="label">Cobertura FS AI RMF</div>'
              f'<div class="value">{coverage["candidatos_supporting"]}/{coverage["total_control_objectives_oficiales"]}</div>'
              f'<div class="unit">SUPPORTING (0 DIRECT)</div></div></div></div>')

    if cross_verify_report.get("skip_reason"):
        h.append(f'<div class="note warn">{cross_verify_report["skip_reason"]}</div>')

    h.append('<h2>2. Benchmark Criptográfico</h2><div class="card"><table>'
              '<thead><tr><th>Métrica</th><th class="num">Firma (ms)</th><th class="num">Verificación (ms)</th></tr></thead><tbody>')
    for k in ["mean", "p50", "p75", "p95", "p99", "p999", "max"]:
        h.append(f'<tr><td>{k}</td><td class="num">{crypto_bench["sign_ms"][k]:.3f}</td>'
                  f'<td class="num">{crypto_bench["verify_ms"][k]:.3f}</td></tr>')
    h.append(f'</tbody></table><div class="note">n={crypto_bench["sign_ms"]["n"]} · '
              f'Throughput firma: <strong>{crypto_bench["sign_throughput_ops_s"]:,.0f} ops/s</strong></div></div>')

    h.append('<h2>3. Cadena de Auditoría</h2><div class="card"><table>'
              '<thead><tr><th>Métrica</th><th class="num">Append (ms)</th></tr></thead><tbody>')
    for k in ["mean", "p50", "p95", "p99", "max"]:
        h.append(f'<tr><td>{k}</td><td class="num">{append_bench["append_ms"][k]:.3f}</td></tr>')
    h.append(f'</tbody></table><div class="note">verify_chain() sobre {entries_n} entradas: '
              f'<strong>{verify_ms:.1f} ms</strong></div></div>')

    h.append('<h2>4. Cobertura Regulatoria (honesta)</h2><div class="card">')
    h.append(f'<p>De los <strong>{coverage["total_control_objectives_oficiales"]}</strong> control objectives '
              f'oficiales del FS AI RMF v1.0, AI-CLAIM aporta evidencia <strong>SUPPORTING</strong> '
              f'(nunca DIRECT) a <strong>{coverage["candidatos_supporting"]}</strong>: '
              + ", ".join(x[0] for x in coverage["detalle"]) + '.</p>')
    h.append(f'<div class="note">{coverage["nota"]}</div></div>')
    h.append(f'<div class="footer">AI-CLAIM — Informe Ejecutivo — {now}<br>'
              f'ML-DSA-65 (FIPS 204) vía liboqs. No certificado FIPS 140-3.</div></div></body></html>')

    content = "".join(h)
    with open(output_path, "w", encoding="utf-8") as f: f.write(content)
    print(f"[OK] Informe generado: {output_path} ({len(content):,} bytes)")
    return output_path


crypto = RealPQCryptoModule()
kp = crypto.generate_keypair()
msg = b"report cross-verify"
xv_report = cross_verify_openssl(msg, crypto.sign(kp, msg), kp.public_key)
cb = benchmark_sign_verify(crypto, n=10000, warmup=200)
ab = benchmark_chain_append(crypto, RealAuditChain, n=300, warmup=20)
vb = benchmark_chain_verify(ab["chain"], sample_sizes=(320,))
cov = coverage_report(sample_chain=ab["chain"])
generate_real_executive_report(cb, ab, vb, cov, xv_report)
