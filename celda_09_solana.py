# ==============================================================================
# AI-CLAIM — Celda 9/22
# ADAPTADOR SOLANA / FÉNIX: publicar hashes de atestación on-chain
# ==============================================================================
import hashlib, time
from typing import Dict, Any, Optional


class FenixSolanaAdapter:
    MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

    def __init__(self, rpc_url="https://api.devnet.solana.com"):
        from solana.rpc.api import Client
        self.client = Client(rpc_url)
        self.rpc_url = rpc_url
        self.network = "devnet" if "devnet" in rpc_url else "mainnet"

    def _build_memo_instruction(self, memo_text, signer_pubkey):
        from solders.instruction import Instruction, AccountMeta
        from solders.pubkey import Pubkey
        memo_program = Pubkey.from_string(self.MEMO_PROGRAM_ID)
        return Instruction(program_id=memo_program,
            accounts=[AccountMeta(signer_pubkey, is_signer=True, is_writable=False)],
            data=memo_text.encode())

    def publish_entry_hash(self, entry_hash, signer_keypair=None):
        from solders.keypair import Keypair
        from solders.transaction import Transaction
        if signer_keypair is None: signer_keypair = Keypair()
        signer_pubkey = signer_keypair.pubkey()
        memo = f"AICLAIM:{entry_hash[:64]}"
        try:
            ix = self._build_memo_instruction(memo, signer_pubkey)
            resp = self.client.get_latest_blockhash()
            recent_blockhash = resp.value.blockhash
            tx = Transaction.new_signed_with_payer(
                [ix], signer_pubkey, [signer_keypair], recent_blockhash)
            send_resp = self.client.send_raw_transaction(bytes(tx))
            return {"success": True, "entry_hash": entry_hash, "memo": memo,
                    "signature": str(send_resp.value), "signer": str(signer_pubkey),
                    "network": self.network,
                    "explorer_url": f"https://explorer.solana.com/tx/{send_resp.value}?cluster={self.network}"}
        except Exception as e:
            msg = str(e).lower()
            is_funds = "insufficient" in msg or "lamports" in msg or "fund" in msg
            return {"success": False, "error": str(e),
                    "error_kind": "insufficient_funds" if is_funds else "unexpected_error",
                    "entry_hash": entry_hash, "network": self.network}

    def verify_attestation_on_chain(self, tx_signature, expected_hash):
        try:
            resp = self.client.get_transaction(tx_signature, encoding="json",
                                                max_supported_transaction_version=0)
            if resp.value is None:
                return {"found": False, "reason": "transacción no encontrada"}
            meta = resp.value.transaction.meta
            logs = meta.log_messages if meta and meta.log_messages else []
            for log in logs:
                if expected_hash[:64] in log:
                    return {"found": True, "expected_hash": expected_hash,
                            "tx_signature": tx_signature, "network": self.network,
                            "explorer_url": f"https://explorer.solana.com/tx/{tx_signature}?cluster={self.network}"}
            return {"found": False, "reason": "hash no encontrado", "tx_signature": tx_signature}
        except Exception as e:
            return {"found": False, "error": str(e)}


def publish_and_verify(adapter, entry_hash, signer_keypair=None):
    pub = adapter.publish_entry_hash(entry_hash, signer_keypair)
    if not pub["success"]: return pub, None
    time.sleep(2)
    return pub, adapter.verify_attestation_on_chain(pub["signature"], entry_hash)


def _run(chain):
    print("=" * 78)
    print("  ADAPTADOR SOLANA / FÉNIX")
    print("=" * 78)
    if len(chain.entries) == 0: chain.append("attested_evaluation", {"demo": True})
    entry_hash = chain.entries[-1].entry_hash
    adapter = FenixSolanaAdapter(rpc_url="https://api.devnet.solana.com")
    print(f"\n  Network: {adapter.network}")
    print(f"  Entry hash: {entry_hash[:32]}...")
    pub, ver = publish_and_verify(adapter, entry_hash)
    if pub["success"]:
        print(f"\n  Publicado")
        print(f"     Signature: {pub['signature']}")
        print(f"     Explorer : {pub['explorer_url']}")
        if ver: print(f"     Verificado on-chain: {ver.get('found')}")
    else:
        kind = pub.get("error_kind")
        if kind == "insufficient_funds":
            print(f"\n  Sin fondos en devnet (esperado): {pub['error']}")
        else:
            print(f"\n  ERROR DE PROGRAMACIÓN: {pub['error']}")
    print("\n" + "=" * 78)
    return pub, ver


crypto = RealPQCryptoModule()
signer = crypto.generate_keypair()
chain = RealAuditChain(crypto=crypto, signer_keypair=signer)
_run(chain)
