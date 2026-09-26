"""Validators for protocol fields and user inputs.

Provides regex-based and range-based validation for telecom identifiers
and general input fields.
"""

from __future__ import annotations

import re
from typing import Optional


def validate_ip_address(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address string.

    Returns:
        True if valid, False otherwise.
    """
    if not ip:
        return False

    # IPv4
    parts = ip.split(".")
    if len(parts) == 4:
        for part in parts:
            try:
                n = int(part)
                if not (0 <= n <= 255):
                    return False
            except ValueError:
                return False
        return True

    # IPv6 (simplified check)
    if ":" in ip:
        return bool(re.match(r"^[0-9a-fA-F:]+$", ip))

    return False


def validate_op_code(code: int) -> bool:
    """Validate a MAP operation code is in a known range.

    Args:
        code: Operation code integer.

    Returns:
        True if in valid range.
    """
    return isinstance(code, int) and 0 <= code <= 255


def validate_risk_score(score: float) -> bool:
    """Validate a risk score is in [0.0, 1.0].

    Args:
        score: Risk score float.

    Returns:
        True if in valid range.
    """
    return isinstance(score, (int, float)) and 0.0 <= float(score) <= 1.0


def validate_timestamp_range(start: str, end: str) -> bool:
    """Validate that a timestamp range is valid (start <= end).

    Args:
        start: ISO-8601 start timestamp.
        end: ISO-8601 end timestamp.

    Returns:
        True if range is valid.
    """
    try:
        from datetime import datetime
        s = datetime.fromisoformat(start)
        e = datetime.fromisoformat(end)
        return s <= e
    except (ValueError, TypeError):
        return False


def validate_gt_country_code(gt_digits: str) -> Optional[str]:
    """Extract and validate the country code from GT digits.

    Args:
        gt_digits: Global Title digit string.

    Returns:
        Extracted country code, or None if unparseable.
    """
    if not gt_digits:
        return None

    digits = gt_digits.lstrip("+")

    # Country codes are 1-3 digits
    # Check known prefixes: 1 (NANP), 2-digit, 3-digit
    if digits.startswith("1"):
        return "1"
    if len(digits) >= 2:
        two_digit = digits[:2]
        if len(digits) >= 3:
            three_digit = digits[:3]
            # 3-digit codes take priority for known ranges
            if three_digit in {"351", "352", "353", "358", "359", "370", "371",
                               "372", "373", "374", "375", "376", "377", "378",
                               "380", "381", "382", "383", "385", "386", "387",
                               "389", "420", "421", "423", "424", "425", "426",
                               "427", "428", "429", "500", "501", "502", "503",
                               "504", "505", "506", "507", "508", "509", "590",
                               "591", "592", "593", "594", "595", "596", "597",
                               "598", "599", "670", "672", "673", "674", "675",
                               "676", "677", "678", "679", "680", "681", "682",
                               "683", "685", "686", "687", "688", "689", "690",
                               "691", "692", "850", "852", "853", "855", "856",
                               "870", "880", "886", "888", "960", "961", "962",
                               "963", "964", "965", "966", "967", "968", "971",
                               "972", "973", "974", "975", "976", "977", "992",
                               "993", "994", "995", "996", "998"}:
                return three_digit
        return two_digit

    return digits[:1] if digits else None
