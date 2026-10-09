# ==============================================================================
# AI-CLAIM — Celda 17/22
# ESTRUCTURA DEL PAQUETE: pyproject + README + LICENSE (Apache 2.0 puro)
# ==============================================================================
import pathlib
import shutil

PKG_ROOT = pathlib.Path("ai_claim_real_pkg")
SRC = PKG_ROOT / "src" / "ai_claim_real"
TESTS = PKG_ROOT / "tests"

if PKG_ROOT.exists():
    shutil.rmtree(PKG_ROOT)
for d in [SRC, TESTS]:
    d.mkdir(parents=True, exist_ok=True)

pyproject = [
    '[build-system]',
    'requires = ["setuptools>=68", "wheel"]',
    'build-backend = "setuptools.build_meta"',
    '',
    '[project]',
    'name = "ai-claim-real"',
    'version = "0.1.0"',
    'description = "Cryptographic attestation layer with ML-DSA-65 (FIPS 204), not FIPS 140-3 certified"',
    'readme = "README.md"',
    'license = { text = "Apache-2.0" }',
    'authors = [{ name = "Pablo Javier Lazarte", email = "contact@ai-claim.example" }]',
    'requires-python = ">=3.10"',
    'keywords = ["ai-governance", "attestation", "fips-204", "ml-dsa", "safr"]',
    'classifiers = [',
    '    "Development Status :: 3 - Alpha",',
    '    "Intended Audience :: Financial and Insurance Industry",',
    '    "License :: OSI Approved :: Apache Software License",',
    '    "Programming Language :: Python :: 3.10",',
    '    "Programming Language :: Python :: 3.11",',
    '    "Programming Language :: Python :: 3.12",',
    '    "Topic :: Security :: Cryptography",',
    ']',
    'dependencies = [',
    '    "liboqs-python>=0.10,<0.11",',
    ']',
    '',
    '[project.optional-dependencies]',
    'service = ["fastapi==0.115.0", "uvicorn[standard]==0.32.0", "pydantic==2.9.2"]',
    'hsm = ["python-pkcs11>=0.7,<0.8"]',
    'solana = ["solana>=0.34,<0.35", "solders>=0.21,<0.22"]',
    'persistence = ["psycopg2-binary==2.9.9"]',
    'dev = ["pytest>=8.0", "pytest-cov>=5.0", "ruff>=0.6"]',
    '',
    '[project.scripts]',
    'ai-claim-real = "ai_claim_real.cli:main"',
    '',
    '[tool.setuptools.packages.find]',
    'where = ["src"]',
    '',
    '[tool.setuptools.package-data]',
    'ai_claim_real = ["py.typed"]',
    '',
    '[tool.pytest.ini_options]',
    'testpaths = ["tests"]',
    'addopts = "-v --tb=short"',
    '',
    '[tool.ruff]',
    'line-length = 100',
    'target-version = "py310"',
]
(PKG_ROOT / "pyproject.toml").write_text("\n".join(pyproject) + "\n")

readme = [
    '# AI-CLAIM (0.1.0 — alpha, sin auditoría externa)',
    '',
    '> Capa de atestación criptográfica con ML-DSA-65 (FIPS 204) vía liboqs.',
    '> **No** certificado FIPS 140-3. **No** auditado externamente todavía.',
    '',
    '**Autor:** Pablo Javier Lazarte, Independent Researcher & Systems Architect',
    '',
    '## Qué es esto (y qué no)',
    '',
    '- La firma criptográfica (ML-DSA-65 vía liboqs) es real, no simulada.',
    '- La verificación cruzada con OpenSSL depende del entorno: OpenSSL 3.5+',
    '  soporta ML-DSA nativamente; versiones anteriores no. Correr',
    '  `pytest` reporta el resultado real en tu entorno, no una cifra fija.',
    '- El log de auditoría (hash-chain + firma) aporta evidencia técnica',
    '  parcial a un número acotado de control objectives del FS AI RMF v1.0',
    '  (ver `ai_claim_real.regulatory` para el detalle honesto: SUPPORTING,',
    '  nunca DIRECT, sobre 230 control objectives oficiales).',
    '',
    '## Quick start',
    '',
    '    pip install -e .[dev]',
    '    pytest',
    '',
    '    from ai_claim_real import RealPQCryptoModule, RealAuditChain',
    '',
    '    crypto = RealPQCryptoModule()',
    '    kp = crypto.generate_keypair()',
    '    sig = crypto.sign(kp, b"message")',
    '    assert crypto.verify(kp.public_key, b"message", sig)',
    '',
    '## Arquitectura',
    '',
    'Dos motores:',
    '- **Motor A (Evaluation):** ejecuta el protocolo congelado, produce un',
    '  resultado determinista. Falla cerrado ante entradas inválidas.',
    '- **Motor B (Attestation):** verifica protocolo y resultado, firma y',
    '  encadena en el log de auditoría. No firma nada que no haya verificado.',
    '',
    'El protocolo se congela (inmutable) atando además el hash del código del',
    'evaluador, el dataset y la semilla — no solo las reglas.',
    '',
    '## Límites conocidos (léase antes de usar en producción)',
    '',
    '- Sin certificación FIPS 140-3.',
    '- Sin auditoría criptográfica externa.',
    '- La cadena de auditoría prueba integridad interna, no que la historia',
    '  sea la única que existió (requiere anclaje externo, ver `expected_head`).',
    '- El mapeo regulatorio es evidencia de apoyo parcial, no certificación',
    '  de cumplimiento.',
    '',
    '## Licencia',
    '',
    'Apache 2.0 (ver LICENSE). Licenciamiento comercial para módulos',
    'enterprise, distribuidos por separado (ver COMMERCIAL_LICENSE.md).',
]
(PKG_ROOT / "README.md").write_text("\n".join(readme) + "\n")

license_text = '''                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

Copyright 2026 Pablo Javier Lazarte

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

NOTICE: The Apache 2.0 license above applies to the AI-CLAIM Community
Edition (files in `src/ai_claim_real/`). It does NOT apply to any
Enterprise Edition or proprietary modules distributed separately.
'''
(PKG_ROOT / "LICENSE").write_text(license_text)
(SRC / "py.typed").write_text("")

print("=" * 78)
print("  ESTRUCTURA DEL PAQUETE — version 0.1.0, sin claims sin respaldo")
print("=" * 78)
for f in sorted(PKG_ROOT.rglob("*")):
    if f.is_file():
        rel = f.relative_to(PKG_ROOT)
        print(f"    {str(rel):45} ({f.stat().st_size:,} bytes)")
print("\n  Siguiente: Celda 18a/18b (módulos del paquete, versión corregida)")
print("=" * 78)
