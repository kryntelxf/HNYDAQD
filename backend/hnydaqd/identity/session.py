import logging
from typing import Optional

from hnydaqd.identity.roles import UserRole

logger = logging.getLogger(__name__)


def determine_role(is_admin: bool, email: Optional[str]) -> UserRole:
    """
    Menentukan role HNYDAQD berdasarkan atribut user Onyx.
    Di Onyx, `is_admin=True` berarti user adalah admin/organisasi owner.
    Email dipakai sebagai fallback untuk demo/scientist.
    """
    if is_admin:
        return UserRole.OWNER

    if email is None:
        return UserRole.INVESTOR

    lower_email = email.lower()
    # Heuristik sederhana; nantinya bisa diganti dengan lookup dari DB
    if "scientist" in lower_email or "lab" in lower_email:
        return UserRole.SCIENTIST
    if "investor" in lower_email or "partner" in lower_email:
        return UserRole.INVESTOR

    return UserRole.INVESTOR
