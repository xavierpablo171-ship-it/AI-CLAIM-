# ==============================================================================
# AI-CLAIM — Celda 20/22
# WHEEL AUDITABLE: build + GPG + hashes + verificación
# ==============================================================================
import subprocess
import sys
import os
import hashlib
import glob

RELEASE_EMAIL = "release@ai-claim.example"


def run(cmd, check=True, quiet=False):
    if not quiet:
        print(f"$ {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.stdout and not quiet:
        print(r.stdout[-2500:])
    if r.stderr and r.returncode != 0:
        print("STDERR:", r.stderr[-1500:])
    if check and r.returncode != 0:
        raise RuntimeError(f"Fallo: {cmd}")
    return r


print("=" * 78)
print("  WHEEL AUDITABLE — Build + Firma + Hashes")
print("=" * 78)

pkg_dir = "ai_claim_real_pkg"
if not os.path.exists(pkg_dir):
    raise FileNotFoundError(f"No existe {pkg_dir}. Ejecuta las celdas 17/18a-c/19 primero.")

os.chdir(pkg_dir)

print("\n[0/5] Asegurando dependencias de build...")
run(f"{sys.executable} -m pip install --quiet --break-system-packages build", check=False)

print("\n[1/5] Limpiando builds anteriores...")
run("rm -rf dist build *.egg-info src/*.egg-info", check=False)
run("rm -f SHA512SUMS* SHA3SUMS* *.asc PUBLIC_KEY.asc", check=False)

print("\n[2/5] Construyendo wheel y sdist...")
run(f"{sys.executable} -m build")

dist_files = sorted(glob.glob("dist/*"))
print(f"\n  Artefactos generados:")
for f in dist_files:
    print(f"    {f} ({os.path.getsize(f):,} bytes)")

print("\n[3/5] Generando hashes SHA512 y SHA3-512...")
sha512_lines, sha3_lines = [], []
for f in dist_files:
    data = open(f, "rb").read()
    sha512, sha3 = hashlib.sha512(data).hexdigest(), hashlib.sha3_512(data).hexdigest()
    sha512_lines.append(f"{sha512}  {os.path.basename(f)}")
    sha3_lines.append(f"{sha3}  {os.path.basename(f)}")
    print(f"    {os.path.basename(f)}: SHA512={sha512[:24]}... SHA3={sha3[:24]}...")

open("SHA512SUMS", "w").write("\n".join(sha512_lines) + "\n")
open("SHA3SUMS", "w").write("\n".join(sha3_lines) + "\n")
print(f"\n  Escrito SHA512SUMS y SHA3SUMS")

print("\n[4/5] Firmando con GPG...")
r = run(f"gpg --list-secret-keys --with-colons {RELEASE_EMAIL} 2>/dev/null | grep -c '^sec'",
        check=False, quiet=True)
has_key = r.stdout.strip() not in ("0", "")

if not has_key:
    print(f"  No hay clave GPG para {RELEASE_EMAIL}. Generando una nueva...")
    batch_config = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Name-Real: AI-CLAIM Release Key\n"
        f"Name-Email: {RELEASE_EMAIL}\n"
        "Expire-Date: 2y\n"
        "%commit\n"
    )
    with open("/tmp/gpg_batch", "w") as f:
        f.write(batch_config)
    run("gpg --batch --generate-key /tmp/gpg_batch", quiet=True)

for f in dist_files:
    if f.endswith((".whl", ".tar.gz")):
        run(f"gpg -u {RELEASE_EMAIL} --detach-sign --armor --yes {f}", quiet=True)
        print(f"    Firmado: {f}.asc")

run(f"gpg -u {RELEASE_EMAIL} --detach-sign --armor --yes SHA512SUMS", quiet=True)
run(f"gpg -u {RELEASE_EMAIL} --detach-sign --armor --yes SHA3SUMS", quiet=True)
run(f"gpg --armor --export {RELEASE_EMAIL} > PUBLIC_KEY.asc", quiet=True)
print(f"    Firmado: SHA512SUMS.asc, SHA3SUMS.asc — Clave pública: PUBLIC_KEY.asc")

print("\n[5/5] Verificando firmas (consistencia interna, NO confianza de terceros)...")
for f in dist_files:
    if f.endswith((".whl", ".tar.gz")):
        r = run(f"gpg --verify {f}.asc {f} 2>&1 | grep -i 'good signature'", check=False, quiet=True)
        print(f"    {os.path.basename(f)}: {'OK (interno)' if 'ood signature' in r.stdout else 'WARN'}")

print("\n[BONUS] Instalando el wheel...")
wheel = [f for f in dist_files if f.endswith(".whl")][0]
run(f"{sys.executable} -m pip install --quiet --break-system-packages --force-reinstall {wheel}")

os.chdir("..")
print("\n" + "=" * 78)
print("  WHEEL AUDITABLE — LISTO")
print("=" * 78)
print("\n  LÍMITE DE CONFIANZA (leer antes de distribuir PUBLIC_KEY.asc):")
print(f"  Esta clave GPG se generó en esta sesión efímera. Nadie puede saber")
print(f"  que '{RELEASE_EMAIL}' te pertenece hasta que:")
print(f"    1) publiques la clave en un keyserver (keys.openpgp.org),")
print(f"    2) la enlaces desde un canal que ya controlás (tu sitio, tus")
print(f"       commits de GitHub firmados con la misma clave), y")
print(f"    3) uses un email real y verificable, no '{RELEASE_EMAIL}'.")
print(f"  Sin eso, [5/5] solo prueba que la firma y la clave son")
print(f"  consistentes entre sí — no que debas confiar en ellas.")
print("=" * 78)
