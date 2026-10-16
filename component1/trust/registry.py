"""
Authorised Device List (ADL) - SQLite-backed device registry.

Every IoMT device must be registered here before it can send telemetry.
Lookup happens BEFORE trust scoring: an unknown device_id is rejected
outright and never reaches the scoring engine.

At registration the device's certificate SHA-256 fingerprint is pinned,
along with its hardware identity (MAC + hardware ID) for the
Fingerprint factor (F) built next.
"""
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

SCHEMA = """
CREATE TABLE IF NOT EXISTS authorised_devices (
    device_id        TEXT PRIMARY KEY,
    device_type      TEXT NOT NULL,
    ambulance_id     TEXT NOT NULL,
    cert_serial      TEXT NOT NULL,
    cert_sha256      TEXT NOT NULL,      -- pinned certificate fingerprint
    mac_address      TEXT NOT NULL,
    hardware_id      TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',  -- active | suspended
    registered_at    TEXT NOT NULL
);
"""


@dataclass
class DeviceRecord:
    device_id: str
    device_type: str
    ambulance_id: str
    cert_serial: str
    cert_sha256: str
    mac_address: str
    hardware_id: str
    status: str
    registered_at: str


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


class DeviceRegistry:
    def __init__(self, db_path: str | Path):
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def register(self, device_id, device_type, ambulance_id, cert_path,
                 mac_address, hardware_id):
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        self.conn.execute(
            "INSERT OR REPLACE INTO authorised_devices VALUES (?,?,?,?,?,?,?,?,?)",
            (device_id, device_type, ambulance_id, format(cert.serial_number, "X"),
             cert_fingerprint(cert), mac_address.lower(), hardware_id,
             "active", datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        self.conn.commit()

    def lookup(self, device_id: str) -> DeviceRecord | None:
        row = self.conn.execute(
            "SELECT * FROM authorised_devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return DeviceRecord(**dict(row)) if row else None

    def is_authorised(self, device_id: str) -> tuple[bool, str]:
        """Pre-scoring gate. Returns (allowed, reason)."""
        rec = self.lookup(device_id)
        if rec is None:
            return False, "UNKNOWN_DEVICE: not on Authorised Device List"
        if rec.status != "active":
            return False, f"DEVICE_{rec.status.upper()}"
        return True, "REGISTERED"

    def all(self) -> list[DeviceRecord]:
        rows = self.conn.execute("SELECT * FROM authorised_devices ORDER BY device_id")
        return [DeviceRecord(**dict(r)) for r in rows]
