import ipaddress
import os
from typing import Any

import requests

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
DEFAULT_TIMEOUT = 14


class AbuseIPDBQueryError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _build_proxies() -> dict[str, str] | None:
    proxy_url = os.getenv("ABUSEIPDB_PROXY_URL", "").strip() or os.getenv("VT_PROXY_URL", "").strip()
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def _validate_ip(ip_address: str) -> str:
    value = (ip_address or "").strip()
    if not value:
        raise ValueError("missing ipAddress parameter")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc


def _extract_error(payload: dict[str, Any], status_code: int) -> str:
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        detail = errors[0].get("detail") if isinstance(errors[0], dict) else None
        if detail:
            return str(detail)

    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("detail") or f"AbuseIPDB request failed with {status_code}")
    if error:
        return str(error)

    return f"AbuseIPDB request failed with {status_code}"


def query_abuseipdb(ip_address: str, api_key: str, max_age_in_days: int = 90) -> dict[str, Any]:
    if not api_key:
        raise ValueError("missing AbuseIPDB API key")

    normalized_ip = _validate_ip(ip_address)
    max_age = max(1, min(int(max_age_in_days or 90), 365))

    response = requests.get(
        f"{ABUSEIPDB_API_BASE}/check",
        params={"ipAddress": normalized_ip, "maxAgeInDays": max_age, "verbose": ""},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=DEFAULT_TIMEOUT,
        proxies=_build_proxies(),
    )

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("AbuseIPDB returned a non-JSON response") from exc

    if response.status_code >= 400:
        raise AbuseIPDBQueryError(_extract_error(payload, response.status_code), status_code=response.status_code)

    data = payload.get("data") or {}
    reports = data.get("reports") or []
    first_report = reports[0] if reports and isinstance(reports[0], dict) else {}

    return {
        "ip_address": data.get("ipAddress") or normalized_ip,
        "is_public": data.get("isPublic"),
        "ip_version": data.get("ipVersion"),
        "is_whitelisted": data.get("isWhitelisted"),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "country_name": data.get("countryName"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames") or [],
        "is_tor": data.get("isTor"),
        "total_reports": data.get("totalReports"),
        "num_distinct_users": data.get("numDistinctUsers"),
        "last_reported_at": data.get("lastReportedAt"),
        "latest_report_comment": first_report.get("comment"),
        "latest_report_categories": first_report.get("categories") or [],
        "raw": data,
    }
