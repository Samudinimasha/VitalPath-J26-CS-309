"""
VitalPath: 5G Security Middleware for Connected Ambulance Telemetry
Component 2: Cryptographic Execution Module (Crypto Engine)

This module implements dynamic cryptographic profiles selected by the SPS Engine:
  - 'Standard':
      * AES-256-GCM encryption (simulating DTLS 1.3 encapsulation)
      * SHA-256 payload integrity digest
      * No per-packet ECDSA signature (conserves vehicular gateway CPU & bandwidth)
      * Relaxed session key rotation (300 seconds)
  - 'Enhanced':
      * AES-256-GCM encryption
      * SHA-256 payload integrity digest
      * Per-packet ECDSA (NIST P-256 / SHA-256) digital signature
      * Moderate session key rotation (60 seconds)
  - 'Maximum':
      * AES-256-GCM encryption with strict binding
      * SHA-256 payload integrity digest
      * Strict ECDSA (NIST P-256 / SHA-256) digital signature with header binding
      * High-frequency session key rotation (10 seconds or handover event triggered)

NFR Compliance:
  - Cryptographic processing must complete well within the per-packet budget (< 20 ms total).
"""

import os
import json
import time
import uuid
import hashlib
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from classifiers import load_config


class KeyManager:
    """
    Manages AES-256 session keys and handles adaptive key rotation based on
    active security profile intervals and network event triggers (e.g. 5G handovers).
    """

    def __init__(self, rotation_intervals: Optional[Dict[str, int]] = None):
        self.intervals = rotation_intervals or {
            "Standard": 300,
            "Enhanced": 60,
            "Maximum": 10,
        }
        self.current_key_id: str = ""
        self.current_session_key: bytes = b""
        self.last_rotation_time: float = 0.0
        self.rotation_count: int = 0
        self.key_history: Dict[str, bytes] = {}
        self.rotate_key(reason="initialization")

    def rotate_key(self, reason: str = "scheduled") -> Tuple[str, bytes]:
        """Generates a fresh 256-bit AES session key."""
        self.current_key_id = f"key_{uuid.uuid4().hex[:8]}"
        self.current_session_key = AESGCM.generate_key(bit_length=256)
        self.last_rotation_time = time.time()
        self.rotation_count += 1
        self.key_history[self.current_key_id] = self.current_session_key
        return self.current_key_id, self.current_session_key

    def check_and_rotate(
        self,
        profile: str,
        handover_event: bool = False,
        now: Optional[float] = None,
    ) -> bool:
        """
        Rotates session key if expiry interval exceeded or if triggered by a cell handover.
        Returns True if a rotation occurred.
        """
        current_time = now if now is not None else time.time()
        interval = self.intervals.get(profile, 60)

        # Event-driven rotation: handover trigger in Maximum profile or interval expiration
        time_expired = (current_time - self.last_rotation_time) >= interval
        event_triggered = handover_event and (profile == "Maximum")

        if time_expired or event_triggered:
            reason = "handover_event" if event_triggered else f"interval_expired_{interval}s"
            self.rotate_key(reason=reason)
            return True

        return False

    def get_key(self, key_id: Optional[str] = None) -> bytes:
        """Retrieves active key or key by identifier."""
        if key_id is None or key_id == self.current_key_id:
            return self.current_session_key
        return self.key_history.get(key_id, self.current_session_key)


class CryptoEngine:
    """
    Cryptographic Execution Module for VitalPath Component 2.
    Applies profile-driven encryption, integrity digests, digital signatures, and key rotation.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config.json",
        private_key: Optional[ec.EllipticCurvePrivateKey] = None,
    ):
        if config is not None:
            self.config = config
        else:
            self.config = load_config(config_path)

        rotation_cfg = self.config.get("key_rotation_seconds", {
            "Standard": 300,
            "Enhanced": 60,
            "Maximum": 10
        })
        self.key_manager = KeyManager(rotation_intervals=rotation_cfg)

        # Generate or assign NIST P-256 ECDSA key pair for vehicular gateway
        if private_key is not None:
            self.private_key = private_key
        else:
            self.private_key = ec.generate_private_key(ec.SECP256R1())

        self.public_key = self.private_key.public_key()

    def secure_packet(
        self,
        payload: Dict[str, Any],
        profile: str,
        packet_id: Optional[str] = None,
        handover_event: bool = False,
    ) -> Dict[str, Any]:
        """
        Encapsulates and secures a telemetry packet according to the active profile.

        Parameters:
            payload (dict): Vital telemetry payload to encrypt.
            profile (str): 'Standard', 'Enhanced', or 'Maximum'.
            packet_id (str, optional): Unique packet sequence identifier.
            handover_event (bool): True if 5G cellular handover in progress.

        Returns:
            dict: Encapsulated secure packet with ciphertext, nonce, digest, signature, and metadata.
        """
        t0 = time.perf_counter()

        pkt_id = packet_id or f"pkt_{uuid.uuid4().hex[:12]}"
        now = time.time()

        # Step 1: Check session key validity / rotation
        rotated = self.key_manager.check_and_rotate(profile, handover_event=handover_event, now=now)
        active_key = self.key_manager.get_key()
        active_key_id = self.key_manager.current_key_id

        # Step 2: Canonical serialization of payload
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        # Step 3: Compute SHA-256 payload integrity digest
        sha256_digest = hashlib.sha256(payload_bytes).hexdigest()

        # Step 4: Conditional ECDSA digital signature based on profile
        signature_hex: Optional[str] = None
        if profile in ("Enhanced", "Maximum"):
            # Maximum signs payload + header binding; Enhanced signs payload digest
            if profile == "Maximum":
                bind_data = f"{pkt_id}:{profile}:{active_key_id}:{sha256_digest}".encode("utf-8")
                sig_bytes = self.private_key.sign(bind_data, ec.ECDSA(hashes.SHA256()))
            else:  # Enhanced
                sig_bytes = self.private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
            signature_hex = sig_bytes.hex()

        # Step 5: DTLS 1.3 encapsulation simulation via AES-256-GCM
        nonce = os.urandom(12)  # 96-bit standard GCM nonce
        
        # Authenticated Additional Data (AAD) binds transport headers to ciphertext
        aad = json.dumps({
            "packet_id": pkt_id,
            "profile": profile,
            "key_id": active_key_id,
        }, sort_keys=True).encode("utf-8")

        aesgcm = AESGCM(active_key)
        ciphertext = aesgcm.encrypt(nonce, payload_bytes, aad)

        crypto_latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "packet_id": pkt_id,
            "profile": profile,
            "key_id": active_key_id,
            "key_rotated": rotated,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "sha256_digest": sha256_digest,
            "ecdsa_signature": signature_hex,
            "crypto_latency_ms": round(crypto_latency_ms, 4),
            "timestamp": now,
        }

    def verify_and_decrypt(
        self,
        secured_packet: Dict[str, Any],
        public_key: Optional[ec.EllipticCurvePublicKey] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Hospital-side receiver simulation: verifies integrity, signatures, and decrypts payload.

        Parameters:
            secured_packet (dict): Encapsulated packet produced by secure_packet.
            public_key (EllipticCurvePublicKey, optional): Sender's public key for signature check.

        Returns:
            Tuple[bool, Optional[dict], str]: (success_flag, decrypted_payload, status_message)
        """
        try:
            pkt_id = secured_packet["packet_id"]
            profile = secured_packet["profile"]
            key_id = secured_packet["key_id"]
            nonce = bytes.fromhex(secured_packet["nonce"])
            ciphertext = bytes.fromhex(secured_packet["ciphertext"])
            claimed_digest = secured_packet["sha256_digest"]
            sig_hex = secured_packet.get("ecdsa_signature")

            # Retrieve key
            key = self.key_manager.get_key(key_id)
            aesgcm = AESGCM(key)

            # Reconstruct AAD
            aad = json.dumps({
                "packet_id": pkt_id,
                "profile": profile,
                "key_id": key_id,
            }, sort_keys=True).encode("utf-8")

            # Decrypt AES-256-GCM
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
            payload = json.loads(plaintext_bytes.decode("utf-8"))

            # Verify SHA-256 digest
            computed_digest = hashlib.sha256(plaintext_bytes).hexdigest()
            if computed_digest != claimed_digest:
                return False, None, "Integrity check failed: SHA-256 digest mismatch"

            # Verify ECDSA digital signature if present
            pk = public_key or self.public_key
            if sig_hex is not None:
                sig_bytes = bytes.fromhex(sig_hex)
                if profile == "Maximum":
                    bind_data = f"{pkt_id}:{profile}:{key_id}:{claimed_digest}".encode("utf-8")
                    pk.verify(sig_bytes, bind_data, ec.ECDSA(hashes.SHA256()))
                else:
                    pk.verify(sig_bytes, plaintext_bytes, ec.ECDSA(hashes.SHA256()))

            return True, payload, "Verification and decryption successful"

        except InvalidSignature:
            return False, None, "Authentication failed: invalid ECDSA signature"
        except Exception as e:
            return False, None, f"Decryption error: {str(e)}"


if __name__ == "__main__":
    cfg = load_config("config.json")
    crypto = CryptoEngine(config=cfg)

    sample_vitals = {
        "patient_id": "AMB_PAT_1042",
        "device_id": "sensor_ecg_01",
        "vitals": {"hr": 84, "spo2": 97, "bp_sys": 122, "bp_dia": 79, "rr": 16},
    }

    print("=" * 78)
    print("VitalPath Component 2: Cryptographic Profiles Verification")
    print("=" * 78)

    for profile in ["Standard", "Enhanced", "Maximum"]:
        sec_pkt = crypto.secure_packet(sample_vitals, profile=profile)
        success, dec_payload, msg = crypto.verify_and_decrypt(sec_pkt)

        has_sig = sec_pkt["ecdsa_signature"] is not None
        print(f"\nProfile: [{profile}]")
        print(f"  Key ID           : {sec_pkt['key_id']}")
        print(f"  ECDSA Signature  : {'Present (P-256 signed)' if has_sig else 'None (Conserves CPU)'}")
        print(f"  SHA-256 Digest   : {sec_pkt['sha256_digest'][:24]}...")
        print(f"  Ciphertext Len   : {len(sec_pkt['ciphertext'])} hex chars")
        print(f"  Crypto Latency   : {sec_pkt['crypto_latency_ms']:.4f} ms")
        print(f"  Receiver Verify  : {msg} (Success: {success})")

    # Benchmark: Run 1,000 packets per profile to benchmark processing latency
    print("\n" + "=" * 78)
    print("Performance Benchmark: Per-Packet Encryption Latency (Target: < 15.0 ms)")
    print("=" * 78)

    for profile in ["Standard", "Enhanced", "Maximum"]:
        times = []
        for _ in range(500):
            t0 = time.perf_counter()
            crypto.secure_packet(sample_vitals, profile=profile)
            times.append((time.perf_counter() - t0) * 1000.0)

        avg_lat = sum(times) / len(times)
        max_lat = max(times)
        print(f"  Profile [{profile:<8}] -> Avg: {avg_lat:.4f} ms | Max: {max_lat:.4f} ms")

    print("=" * 78)

