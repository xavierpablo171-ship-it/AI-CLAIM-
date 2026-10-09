# ==============================================================================
# AI-CLAIM — Celda 3/22
# HSM: PKCS#11 a SoftHSM2 (RSA-2048, NO ML-DSA)
# ==============================================================================
import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import UserAlreadyLoggedIn
import os, subprocess


class RealHSMAdapter:
    def __init__(self, lib_path, token_label, pin):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Librería PKCS#11 no encontrada: {lib_path}")
        self._lib = pkcs11.lib(lib_path)
        self._token = self._lib.get_token(token_label=token_label)
        try:
            self._session = self._token.open(user_pin=pin, rw=True)
        except UserAlreadyLoggedIn:
            self._session = self._token.open(rw=True)
        self.vendor = token_label
        self._keys = {}

    def generate_keypair(self, label):
        public, private = self._session.generate_keypair(
            KeyType.RSA, 2048, label=f"{label}-priv", store=True,
            public_template={Attribute.PUBLIC_EXPONENT: 65537},
            private_template={Attribute.SENSITIVE: True,
                              Attribute.EXTRACTABLE: False, Attribute.SIGN: True})
        handle = str(private.handle)
        self._keys[handle] = (public, private)
        return handle

    def sign(self, handle, data):
        _, priv = self._keys[handle]
        return priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

    def verify(self, handle, data, signature):
        pub, _ = self._keys[handle]
        try:
            return bool(pub.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS))
        except pkcs11.exceptions.SignatureInvalid:
            return False

    def list_objects(self):
        objects = []
        for obj in self._session.get_objects():
            try:
                objects.append({"class": str(obj[Attribute.CLASS]),
                                 "label": str(obj[Attribute.LABEL]),
                                 "handle": str(obj.handle)})
            except pkcs11.exceptions.AttributeTypeInvalid:
                continue
        return objects

    def close(self):
        if getattr(self, "_session", None) is not None:
            self._session.close(); self._session = None


def _find_softhsm_lib():
    for path in ["/usr/lib/softhsm/libsofthsm2.so",
                 "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                 "/usr/local/lib/softhsm/libsofthsm2.so"]:
        if os.path.exists(path): return path
    result = subprocess.run(["find", "/usr", "-name", "libsofthsm2.so"],
                             capture_output=True, text=True)
    found = result.stdout.strip().split("\n")[0]
    if found: return found
    raise FileNotFoundError("SoftHSM2 no encontrado")


def _init_softhsm_token(token_dir, label, so_pin, pin):
    os.makedirs(token_dir, exist_ok=True)
    conf_path = "/tmp/softhsm2.conf"
    with open(conf_path, "w") as f:
        f.write(f"directories.tokendir = {token_dir}\n")
    os.environ["SOFTHSM2_CONF"] = conf_path
    result = subprocess.run(["softhsm2-util", "--init-token", "--free",
         "--label", label, "--so-pin", so_pin, "--pin", pin],
        capture_output=True, text=True)
    print(result.stdout.strip())
    if result.returncode != 0:
        print(result.stderr.strip())
        raise RuntimeError("No se pudo inicializar el token SoftHSM2")


def _run():
    print("=" * 78)
    print("  HSM — PKCS#11 con SoftHSM2 (RSA-2048, no ML-DSA)")
    print("=" * 78)
    _init_softhsm_token("/tmp/softhsm2-tokens", "ai-claim-token", "1234", "5678")
    softhsm_lib = _find_softhsm_lib()
    hsm = RealHSMAdapter(lib_path=softhsm_lib, token_label="ai-claim-token", pin="5678")
    try:
        print(f"\n  HSM vendor        : {hsm.vendor}")
        print(f"  Objetos en token  : {len(hsm.list_objects())}")
        key_handle = hsm.generate_keypair(label="test-key")
        print(f"  Handle            : {key_handle}")
        test_data = b"AI-CLAIM: HSM-backed signing test"
        signature = hsm.sign(key_handle, test_data)
        print(f"  Firma (HSM)       : {len(signature)} bytes")
        ok = hsm.verify(key_handle, test_data, signature)
        tampered_ok = hsm.verify(key_handle, test_data + b"x", signature)
        print(f"  Verificación OK   : {ok}")
        print(f"  Tampering detect. : {not tampered_ok}")
        print("\n" + "=" * 78)
        if ok and not tampered_ok:
            print("  HSM VERIFICADO — interfaz PKCS#11 funcional (RSA-2048)")
        else:
            print("  Verificación falló — revisar")
        print("=" * 78)
    finally:
        hsm.close()


_run()
