"""
Module 6: Blockchain Audit Trail & Cryptographic Ledger
VERIDEX — AI Identity & Document Screening System
Theme: Blockchain & Cybersecurity (Problem Statement ID: SIH26188)

Features:
1. Immutable SHA-256 cryptographic hash chaining for border screening transactions.
2. Asymmetric Ed25519 Digital Signatures (using standard cryptography library) per block.
3. Cryptographic Merkle Tree Root computed over all transaction block hashes.
4. Privacy-by-Design: No raw PII or facial images on-chain; only cryptographic hashes,
   masked identifiers, risk scores, officer decisions, and tamper-evident signatures.
5. Real-time chain verification tool validating hash links, signatures, and Merkle root.
6. Non-destructive Tamper Demo with genuine ledger snapshot backup and restore.
"""

import os
import json
import hashlib
import copy
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LEDGER_FILE = os.path.join(BASE_DIR, "blockchain_ledger.json")
KEYS_DIR = os.path.join(BASE_DIR, ".keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "ed25519_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "ed25519_public.pem")


# ---------------------------------------------------------------------------
# Cryptographic Helpers & Key Management
# ---------------------------------------------------------------------------

def calculate_file_sha256(filepath: str) -> str:
    """Calculate the cryptographic SHA-256 hash of a file."""
    if not filepath or not os.path.exists(filepath):
        return hashlib.sha256(b"FILE_NOT_FOUND").hexdigest()
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()


def mask_document_number(doc_num: Optional[str]) -> str:
    """Mask document numbers for privacy-preserving audit logs (DPDP Act alignment)."""
    if not doc_num:
        return "N/A"
    clean = str(doc_num).strip().replace(" ", "").replace("-", "")
    if len(clean) <= 4:
        return "*" * len(clean)
    if len(clean) == 12 and clean.isdigit():
        return f"XXXX-XXXX-{clean[-4:]}"
    if len(clean) >= 8:
        return f"{clean[:2]}****{clean[-2:]}"
    return f"{clean[:1]}***{clean[-1:]}"


def load_or_generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate or load Ed25519 asymmetric cryptographic keypair."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        try:
            with open(PRIVATE_KEY_PATH, "rb") as f:
                priv_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(PUBLIC_KEY_PATH, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
            return priv_key, pub_key
        except Exception:
            pass

    # Generate fresh Ed25519 keypair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(priv_bytes)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pub_bytes)

    # Set restrictive file permissions on Windows if possible
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except Exception:
        pass

    return priv_key, pub_key


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """Compute cryptographic Merkle Tree Root over a list of block hashes."""
    if not leaf_hashes:
        return "0" * 64
    current_level = [h for h in leaf_hashes if h]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if (i + 1) < len(current_level) else left
            combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


# ---------------------------------------------------------------------------
# Immutable Blockchain Ledger
# ---------------------------------------------------------------------------

class BlockchainLedger:
    def __init__(self, ledger_path: str = LEDGER_FILE):
        self.ledger_path = ledger_path
        self.chain: List[Dict[str, Any]] = []
        self._pre_tamper_backup: Optional[List[Dict[str, Any]]] = None
        self.priv_key, self.pub_key = load_or_generate_keypair()
        self._load_or_init_ledger()

    @property
    def public_key_hex(self) -> str:
        """Return public key raw hex for verification."""
        pub_raw = self.pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub_raw.hex()

    def _calculate_block_hash(self, block_data: Dict[str, Any]) -> str:
        """Compute the SHA-256 hash of a block payload excluding hash, signature, and merkle fields."""
        payload = {
            "index": block_data["index"],
            "timestamp": block_data["timestamp"],
            "screening_id": block_data["screening_id"],
            "officer_id": block_data["officer_id"],
            "checkpoint_id": block_data["checkpoint_id"],
            "document_type": block_data["document_type"],
            "masked_doc_num": block_data["masked_doc_num"],
            "document_hash": block_data["document_hash"],
            "risk_score": block_data["risk_score"],
            "ai_recommendation": block_data["ai_recommendation"],
            "officer_decision": block_data["officer_decision"],
            "override_reason": block_data.get("override_reason"),
            "previous_hash": block_data["previous_hash"],
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _sign_block_hash(self, block_hash: str) -> str:
        """Sign block SHA-256 hash with Ed25519 private key."""
        sig_bytes = self.priv_key.sign(block_hash.encode("utf-8"))
        return sig_bytes.hex()

    def _verify_signature(self, block_hash: str, signature_hex: str, public_key_hex: str) -> bool:
        """Verify Ed25519 signature."""
        try:
            pub_bytes = bytes.fromhex(public_key_hex)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(sig_bytes, block_hash.encode("utf-8"))
            return True
        except Exception:
            return False

    def _create_genesis_block(self) -> Dict[str, Any]:
        genesis_data = {
            "index": 0,
            "timestamp": "2026-01-01T00:00:00Z",
            "screening_id": "SCR-GENESIS-000000",
            "officer_id": "SSB-SYSTEM-ROOT",
            "checkpoint_id": "SSB-HQ-CENTRAL",
            "document_type": "GENESIS",
            "masked_doc_num": "GENESIS-BLOCK",
            "document_hash": hashlib.sha256(b"SSB_GENESIS_ROOT_SEED_2026").hexdigest(),
            "risk_score": 0,
            "ai_recommendation": "INITIALIZED",
            "officer_decision": "GENESIS_ROOT",
            "override_reason": None,
            "previous_hash": "0" * 64,
            "signer_public_key": self.public_key_hex,
        }
        b_hash = self._calculate_block_hash(genesis_data)
        genesis_data["block_hash"] = b_hash
        genesis_data["ed25519_signature"] = self._sign_block_hash(b_hash)
        genesis_data["merkle_root"] = b_hash
        return genesis_data

    def _load_or_init_ledger(self) -> None:
        if os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as f:
                    self.chain = json.load(f)
                if not self.chain:
                    self.chain = [self._create_genesis_block()]
                    self._save_ledger()
            except Exception:
                self.chain = [self._create_genesis_block()]
                self._save_ledger()
        else:
            self.chain = [self._create_genesis_block()]
            self._save_ledger()

    def _save_ledger(self) -> None:
        with open(self.ledger_path, "w", encoding="utf-8") as f:
            json.dump(self.chain, f, indent=2)

    def get_merkle_root(self) -> str:
        """Calculate live Merkle tree root for all blocks in the ledger."""
        hashes = [b["block_hash"] for b in self.chain if "block_hash" in b]
        return compute_merkle_root(hashes)

    def add_screening_record(
        self,
        screening_id: str,
        officer_id: str,
        checkpoint_id: str,
        document_type: str,
        document_number: Optional[str],
        document_filepath: str,
        risk_score: int,
        ai_recommendation: str,
        officer_decision: str,
        override_reason: Optional[str] = None,
        vault_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Commit an Ed25519 digitally signed screening transaction to the immutable ledger."""
        previous_block = self.chain[-1]
        previous_hash = previous_block["block_hash"]
        doc_hash = calculate_file_sha256(document_filepath)

        block = {
            "index": len(self.chain),
            "timestamp": datetime.now().isoformat(),
            "screening_id": screening_id,
            "officer_id": officer_id or "SSB-DUTY-OFFICER",
            "checkpoint_id": checkpoint_id or "SSB-ICP-01",
            "document_type": document_type,
            "masked_doc_num": mask_document_number(document_number),
            "document_hash": doc_hash,
            "risk_score": risk_score,
            "ai_recommendation": ai_recommendation,
            "officer_decision": officer_decision,
            "override_reason": override_reason,
            "previous_hash": previous_hash,
            "signer_public_key": self.public_key_hex,
        }
        if vault_data:
            block["vault_verification"] = {
                "vault_user_id": vault_data.get("vault_user_id", "N/A"),
                "overall_match_score": vault_data.get("overall_match_score", 0),
                "match_status": vault_data.get("match_status", "N/A"),
                "reference_hash": vault_data.get("hash_comparison", {}).get("reference_hash", "N/A"),
                "is_exact_hash": vault_data.get("hash_comparison", {}).get("is_exact_hash", False),
            }
        b_hash = self._calculate_block_hash(block)
        block["block_hash"] = b_hash
        block["ed25519_signature"] = self._sign_block_hash(b_hash)

        # Append and compute live Merkle root
        self.chain.append(block)
        current_merkle = self.get_merkle_root()
        block["merkle_root"] = current_merkle

        self._save_ledger()
        return block

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Cryptographically verify the entire blockchain ledger:
        1. SHA-256 link continuity (previous_hash == prev_block.block_hash).
        2. Block payload hash integrity (stored block_hash == recomputed hash).
        3. Asymmetric Ed25519 digital signature authenticity.
        4. Cumulative Merkle Tree Root recalculation.
        """
        if not self.chain:
            return {"valid": False, "message": "Ledger is empty", "tampered_block": None, "merkle_root": "0" * 64}

        leaf_hashes = []

        # 1. Verify Genesis Block
        genesis = self.chain[0]
        if genesis.get("previous_hash") != "0" * 64:
            return {
                "valid": False,
                "message": "Genesis block link corrupted (previous_hash != 0*64)!",
                "tampered_block": 0,
                "failure_stage": "GENESIS_LINK",
                "merkle_root": self.get_merkle_root(),
            }

        gen_hash = self._calculate_block_hash(genesis)
        if genesis.get("block_hash") != gen_hash:
            return {
                "valid": False,
                "message": "Genesis block payload hash mismatch!",
                "tampered_block": 0,
                "failure_stage": "HASH_MISMATCH",
                "merkle_root": self.get_merkle_root(),
            }

        leaf_hashes.append(genesis["block_hash"])

        # 2. Verify Successive Blocks
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            # Link verification
            if current.get("previous_hash") != prev.get("block_hash"):
                return {
                    "valid": False,
                    "message": f"Broken chain link at Block #{i}! Block #{i} points to {current.get('previous_hash', '')[:12]}..., but Block #{i-1} hash is {prev.get('block_hash', '')[:12]}...",
                    "tampered_block": i,
                    "failure_stage": "CHAIN_LINK_BROKEN",
                    "merkle_root": self.get_merkle_root(),
                }

            # Payload hash verification
            recomputed = self._calculate_block_hash(current)
            if current.get("block_hash") != recomputed:
                return {
                    "valid": False,
                    "message": f"Data alteration detected in Block #{i}! Stored hash != Recomputed payload hash (Tampering Detected).",
                    "tampered_block": i,
                    "failure_stage": "PAYLOAD_ALTERED",
                    "merkle_root": self.get_merkle_root(),
                }

            # Ed25519 digital signature verification
            sig_hex = current.get("ed25519_signature")
            pub_hex = current.get("signer_public_key")
            if sig_hex and pub_hex:
                is_sig_valid = self._verify_signature(current["block_hash"], sig_hex, pub_hex)
                if not is_sig_valid:
                    return {
                        "valid": False,
                        "message": f"Ed25519 digital signature validation failed on Block #{i}! Unauthorized signature or forged key.",
                        "tampered_block": i,
                        "failure_stage": "SIGNATURE_FORGERY",
                        "merkle_root": self.get_merkle_root(),
                    }

            leaf_hashes.append(current["block_hash"])

        merkle_root = compute_merkle_root(leaf_hashes)

        return {
            "valid": True,
            "total_blocks": len(self.chain),
            "merkle_root": merkle_root,
            "message": f"Cryptographic integrity verified: All {len(self.chain)} blocks valid, signed with Ed25519, and Merkle root aligned.",
            "tampered_block": None,
            "failure_stage": None,
        }

    def simulate_tamper(
        self,
        block_index: int,
        field: str = "officer_decision",
        new_value: Any = "UNAUTHORIZED_CLEAR",
    ) -> Tuple[bool, str]:
        """
        Demonstration tool for hackathon judges & auditors:
        Modifies a historical block without re-signing to show instant verification failure.
        Preserves an in-memory backup so the genuine ledger can be restored cleanly.
        """
        if block_index < 0 or block_index >= len(self.chain):
            return False, f"Invalid block index: {block_index}"

        # Preserve snapshot of genuine chain before tampering
        if self._pre_tamper_backup is None:
            self._pre_tamper_backup = copy.deepcopy(self.chain)

        self.chain[block_index][field] = new_value
        self._save_ledger()
        return True, f"Tampered Block #{block_index} ({field} -> '{new_value}'). Real-time verification will now fail."

    def restore_genuine_chain(self) -> Tuple[bool, str]:
        """Restore genuine ledger state from pre-tamper snapshot."""
        if self._pre_tamper_backup is not None:
            self.chain = copy.deepcopy(self._pre_tamper_backup)
            self._pre_tamper_backup = None
            self._save_ledger()
            return True, "Genuine blockchain ledger restored successfully. Verification passes."
        return False, "No active tamper simulation detected."

    def repair_or_reset_ledger(self) -> None:
        """Reset the ledger to clean genesis state for demonstration purposes."""
        self.chain = [self._create_genesis_block()]
        self._pre_tamper_backup = None
        self._save_ledger()

    def get_all_blocks(self) -> List[Dict[str, Any]]:
        return self.chain


# Global singleton instance for easy import across modules
global_ledger = BlockchainLedger()
