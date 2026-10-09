# ==============================================================================
# AI-CLAIM — Celda 21/22
# INSTALACIÓN LIMPIA: Dockerfile verificable desde cero
# ==============================================================================
import pathlib

VERIFY_DIR = pathlib.Path("ai_claim_verify")
VERIFY_DIR.mkdir(exist_ok=True)

dockerfile = '''# AI-CLAIM — Entorno limpio de verificación
FROM python:3.12-slim
WORKDIR /verify

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential cmake ninja-build libssl-dev git gnupg \\
    softhsm2 opensc && \\
    rm -rf /var/lib/apt/lists/*

RUN git clone --branch 0.12.0 --depth=1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs && \\
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON -GNinja && \\
    cmake --build /tmp/liboqs/build --parallel 4 && \\
    cmake --build /tmp/liboqs/build --target install && \\
    ldconfig && rm -rf /tmp/liboqs

ENV LD_LIBRARY_PATH=/usr/local/lib

COPY dist/*.whl /verify/
COPY SHA512SUMS /verify/
COPY SHA512SUMS.asc /verify/
COPY PUBLIC_KEY.asc /verify/
COPY check_install.py /verify/

RUN gpg --import PUBLIC_KEY.asc && \\
    gpg --verify SHA512SUMS.asc SHA512SUMS && \\
    echo "GPG signature OK (consistencia interna)"

RUN sha512sum -c SHA512SUMS && echo "SHA512 hashes OK"

RUN pip install --no-cache-dir /verify/*.whl
RUN pip install --no-cache-dir 'liboqs-python==0.10.1'

RUN python /verify/check_install.py

RUN useradd -m verifier && chown -R verifier /verify
USER verifier

CMD ["python", "-c", "from ai_claim_real import __version__; print(f'ai-claim-real {__version__}')"]
'''
(VERIFY_DIR / "Dockerfile.verify").write_text(dockerfile)

check_install_py = '''"""Verificacion post-instalacion en contenedor limpio."""
from ai_claim_real import RealPQCryptoModule, RealAuditChain, coverage_report

crypto = RealPQCryptoModule()
kp = crypto.generate_keypair()
msg = b"verification from clean install"
sig = crypto.sign(kp, msg)
assert crypto.verify(kp.public_key, msg, sig), "signature failed"

signer = crypto.generate_keypair()
chain = RealAuditChain(crypto, signer)
chain.append("test", {"x": 1})
valid, _ = chain.verify_chain()
assert valid, "chain invalid"

cov = coverage_report()
assert cov["total_control_objectives_oficiales"] == 230, "total FS AI RMF debe ser 230, no 240"
assert cov["candidatos_direct"] == 0, "ningun control debe declararse DIRECT"
assert 0 < cov["candidatos_supporting"] < 10, "cifra de SUPPORTING fuera de rango esperado"

print("OK: instalacion limpia verificada")
print(f"  FS AI RMF v1.0: {cov['total_control_objectives_oficiales']} oficiales, "
      f"SUPPORTING={cov['candidatos_supporting']} DIRECT={cov['candidatos_direct']}")
'''
(VERIFY_DIR / "check_install.py").write_text(check_install_py)

script = '''#!/bin/bash
set -e
echo "=========================================="
echo "  AI-CLAIM - Verificación limpia"
echo "=========================================="
echo "[1/4] Construyendo imagen Docker..."
docker build -f Dockerfile.verify -t ai-claim-verify:latest ../ai_claim_real_pkg 2>&1 | tail -20
echo ""
echo "[2/4] Ejecutando verificación en contenedor limpio..."
docker run --rm ai-claim-verify:latest
echo ""
echo "[3/4] Verificando versión..."
docker run --rm ai-claim-verify:latest python -c "
import ai_claim_real
print(f'Version: {ai_claim_real.__version__}')
print(f'Module: {ai_claim_real.__file__}')
"
echo ""
echo "[4/4] Verificación completada"
echo "OK: El wheel se instala limpiamente en un entorno Docker desde cero"
echo "NOTA: esto verifica reproducibilidad e integridad, NO reemplaza una"
echo "auditoria criptografica externa (ver README.md del paquete)."
'''
(VERIFY_DIR / "verify_clean.sh").write_text(script)

readme = '''# AI-CLAIM - Verificación Limpia

Permite que cualquier tercero verifique la instalación de AI-CLAIM desde
cero, sin confiar en el autor MÁS ALLÁ de la firma GPG generada en la
celda 20 — cuyo límite de confianza (clave efímera, sin anclaje externo)
está documentado ahí. Esto verifica integridad y reproducibilidad, no
sustituye una auditoría criptográfica externa.

## Requisitos
- Docker instalado
- El wheel en `../ai_claim_real_pkg/dist/`
- Los archivos `SHA512SUMS`, `SHA512SUMS.asc`, `PUBLIC_KEY.asc`

## Uso
    cd ai_claim_verify
    bash verify_clean.sh

## Verificación manual (sin Docker)
    gpg --import PUBLIC_KEY.asc
    gpg --verify SHA512SUMS.asc SHA512SUMS
    sha512sum -c SHA512SUMS
    pip install ai_claim_real-0.1.0-py3-none-any.whl
'''
(VERIFY_DIR / "README.md").write_text(readme)

print("=" * 78)
print("  VERIFICACIÓN LIMPIA — corregida contra la API real del paquete")
print("=" * 78)
for f in sorted(VERIFY_DIR.iterdir()):
    if f.is_file():
        print(f"    {f.name:24} ({f.stat().st_size:,} bytes)")
print(f"\n  Uso (después de generar el wheel en la Celda 20):")
print(f"    cd {VERIFY_DIR} && bash verify_clean.sh")
print("=" * 78)
