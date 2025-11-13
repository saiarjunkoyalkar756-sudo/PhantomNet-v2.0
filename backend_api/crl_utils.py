from sqlalchemy.orm import Session
from backend_api.database import RevokedCertificate

def is_certificate_revoked(db: Session, serial_number: str) -> bool:
    """
    Checks if a certificate serial number is in the revocation list.
    """
    return db.query(RevokedCertificate).filter(RevokedCertificate.serial_number == serial_number).first() is not None

def revoke_certificate(db: Session, serial_number: str, reason: str = "Unspecified"):
    """
    Adds a certificate serial number to the revocation list.
    """
    if not is_certificate_revoked(db, serial_number):
        revoked_cert = RevokedCertificate(
            serial_number=serial_number,
            reason=reason
        )
        db.add(revoked_cert)
        db.commit()
        return True
    return False
