"""
CyberRisk-Guidewire-Connector (CRGC)
NVD CVE API v2.0 Client & Parser Service
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, AsyncGenerator, Optional
import httpx

from config.settings import Settings, get_settings

logger = logging.getLogger("crgc.services.nvd_client")


class NvdClientError(Exception):
    """Exception raised for NVD API HTTP or network errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def parse_nvd_timestamp(ts_str: Optional[str]) -> datetime:
    """Parse NVD ISO-8601 timestamp string into timezone-aware UTC datetime."""
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        cleaned = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def extract_cve_metrics(metrics_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Extract CVSS score, severity, version, and vector string across CVSS v4.0, v3.1, v3.0, and v2.0.
    Prioritizes primary V3.1 / V4.0 metrics according to NVD convention.
    """
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        metric_entries = metrics_dict.get(key)
        if not metric_entries or not isinstance(metric_entries, list):
            continue

        # Look for Primary metric first, else take first entry
        primary = next((m for m in metric_entries if m.get("type") == "Primary"), metric_entries[0])
        cvss_data = primary.get("cvssData", {})

        version = cvss_data.get("version") or (key.replace("cvssMetricV", "") if "cvssMetricV" in key else None)
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or primary.get("baseSeverity")
        vector = cvss_data.get("vectorString")

        if base_score is not None:
            try:
                base_score = float(base_score)
            except (ValueError, TypeError):
                base_score = None

        return {
            "cvss_version": str(version) if version else None,
            "cvss_base_score": base_score,
            "cvss_severity": str(severity).upper() if severity else None,
            "cvss_vector": str(vector) if vector else None,
        }

    return {
        "cvss_version": None,
        "cvss_base_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
    }


def parse_nvd_cve_item(item: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a raw NVD CVE JSON record into database model attributes.
    Preserves complete raw payload in 'raw_payload'.
    """
    cve = item.get("cve", item)
    cve_id = cve["id"]

    # 1. Description (prefer English)
    descriptions = cve.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_text = d.get("value", "")
            break
    if not desc_text and descriptions:
        desc_text = descriptions[0].get("value", "")

    # 2. CVSS Metrics
    cvss_metrics = extract_cve_metrics(cve.get("metrics", {}))

    # 3. CWE IDs
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value")
            if val and val not in cwe_ids:
                cwe_ids.append(val)

    # 4. CPE Criteria
    cpe_criteria: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria")
                if crit and crit not in cpe_criteria:
                    cpe_criteria.append(crit)

    # 5. References
    references: list[dict[str, Any]] = []
    for ref in cve.get("references", []):
        references.append({
            "url": ref.get("url"),
            "source": ref.get("source"),
            "tags": ref.get("tags", []),
        })

    return {
        "cve_id": cve_id,
        "source": "NVD",
        "source_identifier": cve.get("sourceIdentifier", "nvd@nist.gov"),
        "published_at": parse_nvd_timestamp(cve.get("published")),
        "last_modified_at": parse_nvd_timestamp(cve.get("lastModified")),
        "vuln_status": cve.get("vulnStatus", "UNKNOWN"),
        "description": desc_text,
        "cvss_version": cvss_metrics["cvss_version"],
        "cvss_base_score": cvss_metrics["cvss_base_score"],
        "cvss_severity": cvss_metrics["cvss_severity"],
        "cvss_vector": cvss_metrics["cvss_vector"],
        "cwe_ids": cwe_ids if cwe_ids else None,
        "cpe_criteria": cpe_criteria if cpe_criteria else None,
        "references_json": references if references else None,
        "raw_payload": cve,
    }


class NvdClient:
    """
    Asynchronous client for NIST National Vulnerability Database (NVD) CVE API v2.0.
    Handles rate-limiting, offset pagination, and API key authentication.
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
                timeout=self.settings.nvd_request_timeout,
                headers={"Accept": "application/json"},
            )
        return self._internal_client

    async def close(self) -> None:
        if self._internal_client and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    async def __aenter__(self) -> "NvdClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def _build_headers(self) -> dict[str, str]:
        """Construct request headers, injecting apiKey securely if configured."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "CRGC-CyberRisk-Guidewire-Connector/1.0",
        }
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
        return headers

    async def fetch_page(
        self,
        cve_id: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        has_kev: Optional[bool] = None,
        results_per_page: int = 2000,
        start_index: int = 0,
    ) -> dict[str, Any]:
        """
        Execute a single paginated GET request to the NVD API 2.0.

        Args:
            cve_id: Specific CVE ID to query.
            pub_start_date: Published date window start.
            pub_end_date: Published date window end.
            last_mod_start_date: Modified date window start.
            last_mod_end_date: Modified date window end.
            has_kev: Filter for CISA KEV presence.
            results_per_page: Number of items per batch.
            start_index: Zero-based starting index.

        Returns:
            dict[str, Any]: Raw JSON response payload from NVD.

        Raises:
            NvdClientError: If HTTP request fails.
        """
        params: dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": max(start_index, 0),
        }

        if cve_id:
            params["cveId"] = cve_id.strip()
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date
        if last_mod_end_date:
            params["lastModEndDate"] = last_mod_end_date
        if has_kev is not None:
            params["hasKev"] = "" if has_kev else "false"

        url = self.settings.nvd_api_base_url
        headers = self._build_headers()
        client = await self._get_client()

        logger.info(
            "Fetching NVD CVE page from %s with params: startIndex=%d, resultsPerPage=%d, cveId=%s",
            url,
            params["startIndex"],
            params["resultsPerPage"],
            params.get("cveId"),
        )

        try:
            response = await client.get(url, params=params, headers=headers)
            if response.status_code != 200:
                logger.error("NVD API returned HTTP %d: %s", response.status_code, response.text)
                raise NvdClientError(
                    f"NVD API request failed with status {response.status_code}: {response.text}",
                    status_code=response.status_code,
                    response_body=response.text,
                )
            return response.json()
        except httpx.RequestError as exc:
            logger.error("Network error communicating with NVD API: %s", str(exc))
            raise NvdClientError(f"Network error connecting to NVD API: {str(exc)}") from exc

    async def fetch_all_vulnerabilities(
        self,
        cve_id: Optional[str] = None,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        has_kev: Optional[bool] = None,
        results_per_page: int = 2000,
        start_index: int = 0,
        max_records: Optional[int] = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """
        Asynchronously paginate through NVD API 2.0 and yield individual raw CVE dictionaries.
        Honors NVD rate limits and configured sleep delays between pages.
        """
        current_index = start_index
        total_retrieved = 0

        while True:
            page_data = await self.fetch_page(
                cve_id=cve_id,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                last_mod_start_date=last_mod_start_date,
                last_mod_end_date=last_mod_end_date,
                has_kev=has_kev,
                results_per_page=results_per_page,
                start_index=current_index,
            )

            vulnerabilities = page_data.get("vulnerabilities", [])
            total_results = page_data.get("totalResults", 0)

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                yield item
                total_retrieved += 1
                if max_records and total_retrieved >= max_records:
                    return

            current_index += len(vulnerabilities)
            if current_index >= total_results:
                break

            # Rate-limiting pause between pages
            if self.settings.nvd_rate_limit_delay > 0:
                await asyncio.sleep(self.settings.nvd_rate_limit_delay)
