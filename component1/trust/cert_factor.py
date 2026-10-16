"""
Certificate Validity factor (C) - weight 0.30 in
    T = 0.30C + 0.25F + 0.20H + 0.15B + 0.10R

C is scored 0.0-1.0 from six checks on the device's X.509 certificate.

HARD FAILURES (C = 0.0 and hard_fail = True):
    1. Not signed by the VitalPath Root CA (forged / rogue CA)
    2. Expired or not yet valid
    3. Revoked (serial on the CA's signed CRL)
    4. Certificate CN does not match the claimed device_id

SOFT PENALTIES (certificate is genuine but needs attention):
    5. Pinned fingerprint mismatch   -> C capped at 0.50
       (genuine CA cert, but not the one registered: re-issued
        without updating the ADL, or a second cert for the same ID)
    6. Missing clientAuth EKU        -> C capped at 0.50
    7. Expires within 30 days        -> C capped at 0.75

Why hard_fail exists: C carries only 30% weight, so a device with
C = 0 but perfect F, H, B, R would still score T = 0.70 and land in
"conditional access". A forged or revoked certificate must never get
any access, so the scoring engine treats hard_fail as an immediate
block regardless of T.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .registry import DeviceRecord, cert_fingerprint

RENEWAL_WINDOW_DAYS = 30


@dataclass
class CertResult:
    score: float
    hard_fail: bool
    checks: dict = field(default_factory=dict)   # check name -> True/False
    reasons: list = field(default_factory=list)  # human-readable findings
    days_to_expiry: int | None = None


class CertificateValidator:
    def __init__(self, ca_cert_path: str | Path, crl_path: str | Path | None = None):
        self.ca = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
        self.crl = None
        if crl_path and Path(crl_path).exists():
            crl = x509.load_pem_x509_crl(Path(crl_path).read_bytes())
            # Only trust a CRL actually signed by our CA
            if crl.is_signature_valid(self.ca.public_key()):
                self.crl = crl

    def evaluate(self, cert_pem: bytes, claimed_id: str,
                 record: DeviceRecord | None = None,
                 now: datetime | None = None) -> CertResult:
        now = now or datetime.now(timezone.utc)
        checks, reasons = {}, []

        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except ValueError:
            return CertResult(0.0, True, {"parseable": False}, ["MALFORMED_CERT"])

        # 1. Chain of trust
        try:
            cert.verify_directly_issued_by(self.ca)
            checks["trusted_issuer"] = True
        except (ValueError, TypeError, InvalidSignature):
            checks["trusted_issuer"] = False
            reasons.append("UNTRUSTED_ISSUER: not signed by VitalPath Root CA")

        # 2. Validity period
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        days_left = (na - now).days
        checks["in_validity_period"] = nb <= now <= na
        if now > na:
            reasons.append(f"EXPIRED on {na.date()}")
        elif now < nb:
            reasons.append(f"NOT_YET_VALID until {nb.date()}")

        # 3. Revocation
        if self.crl is None:
            checks["not_revoked"] = True
            reasons.append("WARN: no CRL loaded, revocation not checked")
        else:
            revoked = self.crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            checks["not_revoked"] = revoked is None
            if revoked is not None:
                reasons.append(f"REVOKED on {revoked.revocation_date_utc.date()}")

        # 4. Identity binding
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cns[0].value if cns else None
        checks["cn_matches_id"] = cn == claimed_id
        if cn != claimed_id:
            reasons.append(f"CN_MISMATCH: cert is for '{cn}', device claims '{claimed_id}'")

        hard_fail = not all(checks[k] for k in
                            ("trusted_issuer", "in_validity_period", "not_revoked", "cn_matches_id"))
        if hard_fail:
            return CertResult(0.0, True, checks, reasons, days_left)

        score = 1.0

        # 5. Fingerprint pinning against the ADL
        if record is not None:
            checks["pin_match"] = cert_fingerprint(cert) == record.cert_sha256
            if not checks["pin_match"]:
                score = min(score, 0.50)
                reasons.append("PIN_MISMATCH: valid cert but not the one registered")

        # 6. Extended Key Usage
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            checks["client_auth_eku"] = ExtendedKeyUsageOID.CLIENT_AUTH in eku
        except x509.ExtensionNotFound:
            checks["client_auth_eku"] = False
        if not checks["client_auth_eku"]:
            score = min(score, 0.50)
            reasons.append("NO_CLIENT_AUTH_EKU")

        # 7. Renewal window
        checks["outside_renewal_window"] = days_left > RENEWAL_WINDOW_DAYS
        if not checks["outside_renewal_window"]:
            score = min(score, 0.75)
            reasons.append(f"EXPIRING_SOON: {days_left} days left")

        if not reasons:
            reasons.append("ALL_CHECKS_PASSED")
        return CertResult(score, False, checks, reasons, days_left)
