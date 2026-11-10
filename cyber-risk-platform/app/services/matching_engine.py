"""
CyberRisk-Guidewire-Connector (CRGC)
Vulnerability Matching Engine (Phase 1A)
Deterministic, explainable organization- and asset-specific vulnerability matching.

Supported Matching Approaches:
1. Exact CVE observation matching from imported authorized scanner findings.
2. Structured CPE 2.3 matching.
3. Vendor and Product normalization and strict equality matching (no naive substring equivalence).
4. Exact version matching.
5. Version-range applicability evaluation when reliable NVD cpeMatch metadata is present.
   (Does not falsely claim range support when metadata lacks range attributes).

Evidence Classifications:
- CONFIRMED:
  A valid, organization-associated scanner observation reports the vulnerability
  against the relevant asset, with its evidence and status available.
- POTENTIAL:
  Asset product/CPE/version information suggests that the vulnerability may apply,
  but there is no sufficient scanner confirmation.
- UNVERIFIED:
  Evidence is incomplete, ambiguous, or insufficient to establish applicability.

Observation Status Lifecycle:
- Active findings: OBSERVED, CONFIRMED (counted toward active confirmed exposure).
- Remediated findings: FIXED (retained for audit, excluded from active exposure).
- Non-issues: FALSE_POSITIVE (retained for audit, excluded from active exposure).
- Ambiguous findings: UNKNOWN (classified as UNVERIFIED).
"""

from datetime import datetime, timezone
from enum import Enum
from functools import total_ordering
import json
import logging
import re
from typing import Any, Optional
import uuid

logger = logging.getLogger(__name__)


class EvidenceClassification(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    UNVERIFIED = "UNVERIFIED"


class MatchingMethod(str, Enum):
    SCANNER_CVE_OBSERVATION = "SCANNER_CVE_OBSERVATION"
    EXACT_CPE_MATCH = "EXACT_CPE_MATCH"
    CPE_VERSION_RANGE_MATCH = "CPE_VERSION_RANGE_MATCH"
    VENDOR_PRODUCT_VERSION_MATCH = "VENDOR_PRODUCT_VERSION_MATCH"
    VENDOR_PRODUCT_RANGE_MATCH = "VENDOR_PRODUCT_RANGE_MATCH"
    VENDOR_PRODUCT_WILDCARD_MATCH = "VENDOR_PRODUCT_WILDCARD_MATCH"
    CPE_PRODUCT_UNVERIFIED_VERSION = "CPE_PRODUCT_UNVERIFIED_VERSION"
    VENDOR_PRODUCT_UNVERIFIED_VERSION = "VENDOR_PRODUCT_UNVERIFIED_VERSION"
    SCANNER_OBSERVATION_UNVERIFIED = "SCANNER_OBSERVATION_UNVERIFIED"


# Common organizational / corporate suffixes to strip during normalization
_ENTITY_SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "ltd", "limited",
    "llc", "gmbh", "co", "company", "technologies", "software", "foundation", "project"
}


def normalize_token(text: Optional[str]) -> str:
    """Lowercases, strips, replaces dashes/dots with underscores."""
    if not text:
        return ""
    # Strip backslash escapes from CPEs (e.g., logo\!_soft -> logo!_soft)
    s = text.strip().lower().replace("\\", "")
    s = re.sub(r"[\s\-_.]+", "_", s).strip("_")
    return s


def normalize_vendor(vendor: Optional[str]) -> str:
    """
    Normalizes a vendor string into a standardized identifier.
    Strips company entity noise words if separated by delimiters.
    """
    token = normalize_token(vendor)
    if not token:
        return ""
    words = token.split("_")
    filtered = [w for w in words if w not in _ENTITY_SUFFIXES]
    return "_".join(filtered) if filtered else token


def normalize_product(product: Optional[str]) -> str:
    """
    Normalizes a product string into a standardized identifier.
    Preserves numeric markers and versions in product names (e.g. log4j vs log4j2).
    Never uses lossy stemmers that could conflate different products.
    """
    token = normalize_token(product)
    if not token:
        return ""
    # Strip leading vendor name if prefixed e.g. apache_log4j -> log4j
    words = token.split("_")
    if len(words) > 1 and words[0] in {"apache", "google", "microsoft", "oracle", "mozilla"}:
        words = words[1:]
    return "_".join(words) if words else token


@total_ordering
class ComparableVersion:
    """
    Deterministic version comparator.
    Handles numeric sequences, alphanumeric patch tags (e.g., 1.1.1k),
    and pre-release markers (alpha, beta, rc).
    """
    def __init__(self, raw: Optional[str]):
        self.raw = (raw or "").strip()
        self.is_empty = not bool(self.raw) or self.raw in ("*", "-")
        self.parsed = self._parse(self.raw) if not self.is_empty else ([], 0, [])

    @staticmethod
    def _parse(s: str) -> tuple[list[tuple[int, Any]], int, list[tuple[int, Any]]]:
        parts = re.split(r"[-_]", s.strip().lower())
        main_part = parts[0]
        prerelease = parts[1:] if len(parts) > 1 else []

        main_tokens = re.findall(r"(\d+|\D+)", main_part)
        parsed_main: list[tuple[int, Any]] = []
        for t in main_tokens:
            if t.isdigit():
                parsed_main.append((0, int(t)))
            else:
                cleaned = t.strip(".-_")
                if cleaned:
                    parsed_main.append((1, cleaned))

        # Normalize trailing zeroes in main: 2.0 == 2.0.0
        while len(parsed_main) > 1 and parsed_main[-1] == (0, 0):
            parsed_main.pop()

        parsed_pre: list[tuple[int, Any]] = []
        for p in prerelease:
            for t in re.findall(r"(\d+|\D+)", p):
                if t.isdigit():
                    parsed_pre.append((0, int(t)))
                else:
                    c = t.strip(".-_")
                    if c:
                        parsed_pre.append((1, c))

        is_release = 1 if not parsed_pre else 0
        return (parsed_main, is_release, parsed_pre)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ComparableVersion):
            return False
        if self.is_empty or other.is_empty:
            return False
        return self.parsed == other.parsed

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, ComparableVersion):
            return NotImplemented
        if self.is_empty or other.is_empty:
            return False
        return self.parsed < other.parsed

    def __repr__(self) -> str:
        return f"<ComparableVersion({self.raw})>"


class ParsedCPE:
    """
    Parses and holds structured CPE 2.3 criteria.
    cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    def __init__(self, cpe_string: Optional[str]):
        self.raw = (cpe_string or "").strip()
        self.is_valid = False
        self.part: str = ""
        self.vendor: str = ""
        self.product: str = ""
        self.version: str = ""
        self.update: str = ""
        self.norm_vendor: str = ""
        self.norm_product: str = ""

        if self.raw.startswith("cpe:2.3:"):
            # Split with escaped colons preserved
            tokens = self._split_cpe(self.raw)
            if len(tokens) >= 5:
                self.is_valid = True
                self.part = tokens[2]
                self.vendor = tokens[3]
                self.product = tokens[4]
                self.version = tokens[5] if len(tokens) > 5 else "*"
                self.update = tokens[6] if len(tokens) > 6 else "*"
                self.norm_vendor = normalize_vendor(self.vendor)
                self.norm_product = normalize_product(self.product)

    @staticmethod
    def _split_cpe(cpe_str: str) -> list[str]:
        parts: list[str] = []
        cur: list[str] = []
        escaped = False
        for ch in cpe_str:
            if escaped:
                cur.append(ch)
                escaped = False
            elif ch == "\\":
                cur.append(ch)
                escaped = True
            elif ch == ":":
                parts.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        parts.append("".join(cur))
        return parts


def evaluate_version_range(
    asset_version_str: Optional[str],
    cpe_match: dict[str, Any],
) -> tuple[Optional[bool], str]:
    """
    Evaluates asset version against NVD cpeMatch version range criteria.
    Returns:
    - (True, reason) if strictly within range.
    - (False, reason) if strictly outside range.
    - (None, reason) if metadata lacks range support or asset version is missing.
    """
    if not asset_version_str or asset_version_str.strip() in ("*", "-"):
        return (None, "Asset version is missing or unspecified; range applicability cannot be determined.")

    asset_ver = ComparableVersion(asset_version_str)
    if asset_ver.is_empty:
        return (None, "Asset version could not be parsed into comparable segments.")

    start_inc = cpe_match.get("versionStartIncluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc = cpe_match.get("versionEndIncluding")
    end_exc = cpe_match.get("versionEndExcluding")

    has_range_metadata = any([start_inc, start_exc, end_inc, end_exc])
    if not has_range_metadata:
        return (None, "Vulnerability cpeMatch record does not define start/end version ranges.")

    range_desc_parts = []

    # Check start boundary
    if start_inc:
        v_start = ComparableVersion(start_inc)
        range_desc_parts.append(f">= {start_inc}")
        if asset_ver < v_start:
            return (False, f"Asset version '{asset_version_str}' is below start boundary >= {start_inc}.")

    if start_exc:
        v_start_exc = ComparableVersion(start_exc)
        range_desc_parts.append(f"> {start_exc}")
        if asset_ver <= v_start_exc:
            return (False, f"Asset version '{asset_version_str}' is below or at start boundary > {start_exc}.")

    # Check end boundary
    if end_inc:
        v_end = ComparableVersion(end_inc)
        range_desc_parts.append(f"<= {end_inc}")
        if asset_ver > v_end:
            return (False, f"Asset version '{asset_version_str}' exceeds end boundary <= {end_inc}.")

    if end_exc:
        v_end_exc = ComparableVersion(end_exc)
        range_desc_parts.append(f"< {end_exc}")
        if asset_ver >= v_end_exc:
            return (False, f"Asset version '{asset_version_str}' reaches or exceeds end boundary < {end_exc}.")

    range_summary = " and ".join(range_desc_parts)
    return (True, f"Asset version '{asset_version_str}' satisfies NVD version range [{range_summary}].")


def reconcile_observations(observations: list[Any]) -> dict[str, Any]:
    """
    Reconciles multiple scanner observations for the same asset and CVE.
    Handles:
    - Active observations (CONFIRMED, OBSERVED)
    - Remediated observations (FIXED)
    - Non-issues (FALSE_POSITIVE)
    - Ambiguous observations (UNKNOWN)
    - Conflicting observations across scanners or runs

    Sorts by observed_at descending to determine current effective status.
    Preserves all observation history, source tools, and timestamps.
    """
    if not observations:
        return {
            "effective_status": None,
            "evidence_classification": EvidenceClassification.UNVERIFIED.value,
            "is_active_exposure": False,
            "has_conflict": False,
            "conflict_details": None,
            "primary_observation": None,
            "sources": [],
            "count": 0,
        }

    # Sort descending by observed_at (or created_at fallback)
    sorted_obs = sorted(
        observations,
        key=lambda o: (
            getattr(o, "observed_at", None) or getattr(o, "created_at", None) or datetime.min.replace(tzinfo=timezone.utc)
        ),
        reverse=True,
    )

    primary = sorted_obs[0]
    sources = list({o.scanner_source for o in sorted_obs if getattr(o, "scanner_source", None)})
    all_statuses = [o.status.upper() for o in sorted_obs if getattr(o, "status", None)]

    distinct_statuses = set(all_statuses)
    has_conflict = len(distinct_statuses) > 1

    # Format conflict details if conflicting statuses exist
    conflict_details = None
    if has_conflict:
        details = [
            f"{o.scanner_source} reported {o.status} at {o.observed_at.isoformat() if hasattr(o.observed_at, 'isoformat') else o.observed_at}"
            for o in sorted_obs
        ]
        conflict_details = f"Conflicting observation reports: {'; '.join(details)}."

    effective_status = primary.status.upper() if getattr(primary, "status", None) else "UNKNOWN"

    if effective_status in ("CONFIRMED", "OBSERVED"):
        classification = EvidenceClassification.CONFIRMED.value
        is_active = True
    elif effective_status == "FIXED":
        classification = EvidenceClassification.UNVERIFIED.value
        is_active = False  # Fixed findings are not active exposure
    elif effective_status == "FALSE_POSITIVE":
        classification = EvidenceClassification.UNVERIFIED.value
        is_active = False  # False positives are not active exposure
    else:
        classification = EvidenceClassification.UNVERIFIED.value
        is_active = False

    return {
        "effective_status": effective_status,
        "evidence_classification": classification,
        "is_active_exposure": is_active,
        "has_conflict": has_conflict,
        "conflict_details": conflict_details,
        "primary_observation": primary,
        "all_observations": sorted_obs,
        "sources": sources,
        "count": len(sorted_obs),
    }
