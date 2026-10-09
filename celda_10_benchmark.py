# ==============================================================================
# AI-CLAIM — Celda 10/22
# BENCHMARK con p50/p75/p95/p99/p999 — n=10.000
# ==============================================================================
import os, sys, json, time, platform, statistics
from typing import Dict, List


def _percentiles(data):
    s = sorted(data); n = len(s)
    return {"mean": statistics.mean(s),
            "stdev": statistics.stdev(s) if n > 1 else 0.0,
            "min": s[0],
            "p50": s[int(0.50 * n)], "p75": s[int(0.75 * n)],
            "p90": s[int(0.90 * n)], "p95": s[int(0.95 * n)],
            "p99": s[int(0.99 * n)],
            "p999": s[min(int(0.999 * n), n - 1)],
            "max": s[-1], "n": n}


def benchmark_sign_verify(crypto, n=10_000, warmup=200):
    kp = crypto.generate_keypair()
    msg = b"benchmark message for ML-DSA-65 percentiles"
    for _ in range(warmup):
        s = crypto.sign(kp, msg); crypto.verify(kp.public_key, msg, s)
    sign_lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns(); crypto.sign(kp, msg)
        sign_lat.append((time.perf_counter_ns() - t0) / 1e6)
    last_sig = crypto.sign(kp, msg)
    verify_lat = []
    for _ in range(n):
        t0 = time.perf_counter_ns(); crypto.verify(kp.public_key, msg, last_sig)
        verify_lat.append((time.perf_counter_ns() - t0) / 1e6)
    return {"n": n, "warmup": warmup,
            "sign_ms": _percentiles(sign_lat),
            "verify_ms": _percentiles(verify_lat),
            "sign_throughput_ops_s": 1000 / statistics.mean(sign_lat),
            "verify_throughput_ops_s": 1000 / statistics.mean(verify_lat)}


def benchmark_chain_append(crypto, chain_cls, n=2_000, warmup=50):
    signer = crypto.generate_keypair()
    chain = chain_cls(crypto, signer)
    for i in range(warmup): chain.append("warmup", {"i": i})
    lat = []
    for i in range(n):
        t0 = time.perf_counter_ns()
        chain.append("attested_evaluation", {"i": i, "amount_cents": 100_000 + i})
        lat.append((time.perf_counter_ns() - t0) / 1e6)
    return {"n": n, "append_ms": _percentiles(lat), "chain": chain}


def benchmark_chain_verify(chain, sample_sizes=(100, 1_000, 5_000)):
    results = {}
    for size in sample_sizes:
        if size > len(chain.entries): continue
        t0 = time.perf_counter_ns()
        valid, _ = chain.verify_chain()
        elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
        results[size] = {"elapsed_ms": elapsed_ms, "valid": valid,
                          "actual_chain_length": len(chain.entries)}
    return results


def _run():
    print("=" * 78)
    print("  BENCHMARK — p50/p75/p95/p99/p999")
    print("=" * 78)
    print(f"\n  Python: {sys.version.split()[0]} | Platform: {platform.platform()} | "
          f"CPU: {os.cpu_count()}")
    crypto = RealPQCryptoModule()
    N = 10_000
    print(f"\n  [1/3] Firma y verificación ML-DSA-65 (n={N})...")
    cb = benchmark_sign_verify(crypto, n=N, warmup=200)
    for label, d in [("FIRMA", cb["sign_ms"]), ("VERIFICACIÓN", cb["verify_ms"])]:
        print(f"\n  {label} (ms), n={d['n']}:")
        for k in ["mean", "stdev", "min", "p50", "p75", "p90", "p95", "p99", "p999", "max"]:
            print(f"    {k:8} : {d[k]:>10.4f}")
    print(f"\n  Throughput firma: {cb['sign_throughput_ops_s']:,.0f} ops/s")
    print(f"  Throughput verify: {cb['verify_throughput_ops_s']:,.0f} ops/s")

    print(f"\n  [2/3] Append a la cadena (n=2000)...")
    ab = benchmark_chain_append(crypto, RealAuditChain, n=2_000, warmup=50)
    for k in ["mean", "stdev", "min", "p50", "p95", "p99", "max"]:
        print(f"    {k:8} : {ab['append_ms'][k]:>10.4f}")

    print(f"\n  [3/3] verify_chain() completo...")
    vb = benchmark_chain_verify(ab["chain"], sample_sizes=(2_050,))
    for size, r in vb.items():
        print(f"    cadena de {r['actual_chain_length']} entradas -> "
              f"{r['elapsed_ms']:.2f} ms (válida: {r['valid']})")

    report = {"environment": {"python": sys.version.split()[0],
                              "platform": platform.platform(), "cpu_count": os.cpu_count()},
              "crypto_benchmark": cb,
              "append_benchmark": {"n": ab["n"], "append_ms": ab["append_ms"]},
              "verify_chain_benchmark": vb}
    with open("BENCHMARK_REPORT.json", "w") as f: json.dump(report, f, indent=2)
    print(f"\n  Reporte: BENCHMARK_REPORT.json")
    print("\n" + "=" * 78)
    return report


_run()
