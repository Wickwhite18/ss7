"""Format parsers for telecom identifiers.

Extracts structured components from IMSI, GT, and MSISDN strings.
"""

from __future__ import annotations

from typing import Optional

from .validators import validate_gt_country_code


def parse_imsi(imsi: str) -> dict[str, Optional[str]]:
    """Parse an IMSI into MCC (mobile country code) and MNC (mobile network code).

    IMSI format: MCC (3 digits) + MNC (2-3 digits) + MSIN (remaining digits).

    Args:
        imsi: 15-digit IMSI string.

    Returns:
        Dict with mcc, mnc, msin fields.
    """
    if not imsi or not imsi.isdigit():
        return {"mcc": None, "mnc": None, "msin": None, "raw": imsi}

    return {
        "mcc": imsi[:3] if len(imsi) >= 3 else None,
        "mnc": imsi[3:5] if len(imsi) >= 5 else None,
        "msin": imsi[5:] if len(imsi) > 5 else None,
        "raw": imsi,
    }


def parse_gt(gt_digits: str) -> dict[str, Optional[str]]:
    """Parse a Global Title into country code and national number.

    Args:
        gt_digits: GT digit string (optionally with + prefix).

    Returns:
        Dict with country_code, national_number, raw fields.
    """
    if not gt_digits:
        return {"country_code": None, "national_number": None, "raw": gt_digits}

    digits = gt_digits.lstrip("+")
    cc = validate_gt_country_code(digits)

    if cc:
        national = digits[len(cc):]
    else:
        national = digits

    return {
        "country_code": cc,
        "national_number": national if national else None,
        "raw": gt_digits,
    }


def parse_msisdn(msisdn: str) -> dict[str, Optional[str]]:
    """Parse an MSISDN into country code and subscriber number.

    Args:
        msisdn: MSISDN string (optionally with + prefix).

    Returns:
        Dict with country_code, subscriber_number, raw fields.
    """
    if not msisdn:
        return {"country_code": None, "subscriber_number": None, "raw": msisdn}

    digits = msisdn.lstrip("+")
    cc = validate_gt_country_code(digits)

    if cc:
        subscriber = digits[len(cc):]
    else:
        subscriber = digits

    return {
        "country_code": cc,
        "subscriber_number": subscriber if subscriber else None,
        "raw": msisdn,
    }


def parse_op_code_name(code: int) -> str:
    """Return the human-readable name for a MAP operation code.

    Args:
        code: MAP operation code.

    Returns:
        Name string, or "Unknown (code)" for unrecognized codes.
    """
    names = {
        2: "Update Location",
        3: "Provide Subscriber Info (PSI)",
        22: "Send Routing Info (SRI)",
        45: "Send Routing Info for SM (SRI-SM)",
    }
    return names.get(code, f"Unknown ({code})")
