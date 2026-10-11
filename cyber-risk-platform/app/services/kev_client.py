"""
CyberRisk-Guidewire-Connector (CRGC)
CISA Known Exploited Vulnerabilities (KEV) Catalog Client & Normalizer
"""

from datetime import date, datetime, timezone
import logging
from typing import Any, Optional
import httpx

from config.settings import Settings, get_settings

logger = logging.getLogger("crgc.services.kev_client")


class CisaKevClientError(Exception):
    """Exception raised for CISA KEV network or HTTP errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def parse_kev_date(date_str: Optional[str]) -> Optional[date]:
    """Parse 'YYYY-MM-DD' date string into Python datetime.date."""
    if not date_str:
        return None
    try:
        return date.fromisoformat(date_str.strip())
    except (ValueError, TypeError):
        return None


def parse_known_ransomware_use(raw_val: Optional[str]) -> Optional[bool]:
    """Parse 'Known' / 'Unknown' ransomware campaign utilization indicator."""
    if not raw_val:
        return None
    val = raw_val.strip().lower()
    if "known" in val and "unknown" not in val:
        return True
    elif "unknown" in val:
        return False
    return None


def parse_kev_entry(entry: dict[str, Any], source_url: str) -> dict[str, Any]:
    """
    Normalize a single raw CISA KEV catalog vulnerability entry into model attributes.
    Preserves original KEV item dictionary in 'raw_payload'.
    """
    cve_id = entry.get("cveID", "").strip()
    return {
        "cve_id": cve_id,
        "vulnerability_name": entry.get("vulnerabilityName"),
        "kev_date_added": parse_kev_date(entry.get("dateAdded")),
        "kev_due_date": parse_kev_date(entry.get("dueDate")),
        "required_action": entry.get("requiredAction"),
        "known_ransomware_use": parse_known_ransomware_use(entry.get("knownRansomwareCampaignUse")),
        "kev_flag": True,
        "source": "CISA_KEV",
        "source_url": source_url,
        "retrieved_at": datetime.now(timezone.utc),
        "raw_payload": entry,
    }


class CisaKevClient:
    """
    Asynchronous client for CISA Known Exploited Vulnerabilities (KEV) Catalog.
    Downloads and streams the official JSON feed.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self._external_client = client
        self._internal_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._external_client:
            return self._external_client
        if self._internal_client is None or self._internal_client.is_closed:
            self._internal_client = httpx.AsyncClient(
                timeout=self.settings.cisa_kev_request_timeout,
                headers={"Accept": "application/json", "User-Agent": "CRGC-CyberRisk-Guidewire-Connector/1.0"},
            )
        return self._internal_client

    async def close(self) -> None:
        if self._internal_client and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    async def __aenter__(self) -> "CisaKevClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def fetch_catalog(self) -> dict[str, Any]:
        """
        Download the full CISA Known Exploited Vulnerabilities catalog JSON.

        Returns:
            dict[str, Any]: Parsed KEV catalog payload containing 'vulnerabilities' list.

        Raises:
            CisaKevClientError: If network error or non-200 HTTP response occurs.
        """
        url = self.settings.cisa_kev_catalog_url
        client = await self._get_client()

        logger.info("Fetching CISA KEV catalog from %s", url)
        try:
            response = await client.get(url)
            if response.status_code != 200:
                logger.error("CISA KEV fetch failed with status %d: %s", response.status_code, response.text)
                raise CisaKevClientError(
                    f"CISA KEV catalog request failed with status {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text,
                )
            return response.json()
        except httpx.RequestError as exc:
            logger.error("Network communication error with CISA KEV endpoint: %s", str(exc))
            raise CisaKevClientError(f"Network error connecting to CISA KEV endpoint: {str(exc)}") from exc
