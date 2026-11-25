"""Shared CVSS v3.0 / v3.1 parsing, scoring, and severity-mapping helpers."""

from typing import Optional, Tuple
from cvss import CVSS3, CVSSError

from app.modules.findings.models import FindingSeverity


def score_to_severity(score: float) -> FindingSeverity:
    """Map a CVSS v3.x base score (0.0-10.0) to FindingSeverity."""
    if score < 0.0 or score > 10.0:
        raise ValueError("CVSS score must be between 0.0 and 10.0.")
    rounded = round(score, 1)
    if rounded == 0.0:
        return FindingSeverity.INFO
    if rounded <= 3.9:
        return FindingSeverity.LOW
    if rounded <= 6.9:
        return FindingSeverity.MEDIUM
    if rounded <= 8.9:
        return FindingSeverity.HIGH
    return FindingSeverity.CRITICAL


def validate_cvss_vector_v3(vector: Optional[str]) -> Optional[str]:
    """
    Validate and normalize a CVSS v3.0 or v3.1 vector string.
    Rejects CVSS v4.0 and malformed vectors.
    """
    if vector is None:
        return None
    clean = vector.strip()
    if not clean:
        return None

    if clean.startswith("CVSS:4."):
        raise ValueError(
            "CVSS v4.0 vectors are not supported; please provide a CVSS v3.0 or v3.1 vector."
        )
    if not (clean.startswith("CVSS:3.0/") or clean.startswith("CVSS:3.1/")):
        raise ValueError("CVSS vector must begin with CVSS:3.0/ or CVSS:3.1/.")

    try:
        CVSS3(clean)
    except CVSSError as exc:
        raise ValueError(f"Invalid CVSS v3 vector: {exc}") from exc

    return clean


def validate_and_resolve_cvss(
    *,
    severity: Optional[FindingSeverity],
    cvss_score: Optional[float],
    cvss_vector: Optional[str],
) -> Tuple[Optional[float], Optional[str], Optional[FindingSeverity]]:
    """
    Validate CVSS inputs with the vector as the single source of truth.

    - If a vector is provided: parse it, compute base score, derive severity,
      and reject any client-supplied cvss_score or severity that disagrees.
    - If no vector is provided: reject standalone cvss_score, allow severity alone,
      and return (None, None, severity).
    """
    clean_vector = validate_cvss_vector_v3(cvss_vector)

    if clean_vector is None:
        if cvss_score is not None:
            raise ValueError(
                "cvss_score cannot be provided without a valid CVSS v3.0/v3.1 cvss_vector."
            )
        return None, None, severity

    parsed = CVSS3(clean_vector)
    computed_score = float(parsed.base_score)
    derived_severity = score_to_severity(computed_score)

    if cvss_score is not None and round(cvss_score, 1) != round(computed_score, 1):
        raise ValueError(
            f"Provided cvss_score ({cvss_score}) does not match CVSS vector base score ({computed_score})."
        )

    if severity is not None and severity != derived_severity:
        sev_label = severity.value if hasattr(severity, "value") else str(severity)
        raise ValueError(
            f"Selected severity '{sev_label}' does not match CVSS score {computed_score} "
            f"(expected '{derived_severity.value}')."
        )

    return computed_score, clean_vector, derived_severity
