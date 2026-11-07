import os
from typing import Any
from urllib.parse import urlparse

import requests

VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 14


class VTQueryError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def detect_ioc_type(ioc: str) -> str:
    value = (ioc or "").strip()
    if not value:
        raise ValueError("IOC 不能为空。")

    lowered = value.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return "URL"

    hash_lengths = {32: "MD5", 40: "SHA1", 64: "SHA256"}
    if len(value) in hash_lengths and all(ch in "0123456789abcdefABCDEF" for ch in value):
        return hash_lengths[len(value)]

    ipv4_parts = value.replace("[", "").replace("]", "").split(".")
    if len(ipv4_parts) == 4:
        try:
            octets = [int(part) for part in ipv4_parts]
        except ValueError:
            octets = []
        if octets and all(0 <= part <= 255 for part in octets):
            return "IP"

    if "." in value and " " not in value:
        return "Domain"

    raise ValueError("无法识别 IOC 类型，请输入 IP、域名、URL 或文件 Hash。")


def normalize_ioc(ioc: str, ioc_type: str) -> str:
    value = (ioc or "").strip()
    normalized_type = (ioc_type or "").strip().upper()

    if normalized_type == "URL":
        parsed = urlparse(value)
        if parsed.netloc:
            return parsed.netloc
        if "://" not in value and "/" in value:
            return value.split("/")[0]
        return value

    if normalized_type in {"DOMAIN", "DOMIAN"}:
        if "://" in value:
            parsed = urlparse(value)
            if parsed.netloc:
                return parsed.netloc
        return value.split("/")[0].replace("[", "").replace("]", "")

    if normalized_type == "IP":
        return value.replace("[", "").replace("]", "")

    return value


def _build_proxies() -> dict[str, str] | None:
    proxy_url = os.getenv("VT_PROXY_URL", "").strip()
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def _extract_vendor_verdict(results: dict[str, Any], vendor: str) -> str:
    vendor_result = results.get(vendor) or {}
    if vendor_result.get("category") == "malicious":
        return "malicious"
    return "N"


def _fetch_vt_resource(resource: str, value: str, api_key: str) -> dict[str, Any]:
    response = requests.get(
        f"{VT_API_BASE}/{resource}/{value}",
        headers={"accept": "application/json", "x-apikey": api_key},
        timeout=DEFAULT_TIMEOUT,
        proxies=_build_proxies(),
    )

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("VirusTotal 返回了非 JSON 响应。") from exc

    if response.status_code >= 400:
        error = payload.get("error") or {}
        message = error.get("message") or f"VirusTotal 请求失败，状态码 {response.status_code}。"
        raise VTQueryError(message, status_code=response.status_code)

    if "error" in payload:
        raise VTQueryError(payload["error"].get("message", "VirusTotal 查询失败。"), status_code=response.status_code)

    return payload


def query_ioc(ioc: str, api_key: str, ioc_type: str | None = None) -> dict[str, Any]:
    if not api_key:
        raise ValueError("缺少 VT API Key。")

    resolved_type = (ioc_type or detect_ioc_type(ioc)).strip()
    normalized = normalize_ioc(ioc, resolved_type)
    upper_type = resolved_type.upper()

    if upper_type in {"HASH", "MD5", "SHA1", "SHA256"}:
        resource = "files"
        response_type = "Hash"
    elif upper_type == "IP":
        resource = "ip_addresses"
        response_type = "IP"
    elif upper_type in {"DOMAIN", "DOMIAN", "URL"}:
        resource = "domains"
        response_type = "Domain"
    else:
        raise ValueError(f"暂不支持的 IOC 类型: {resolved_type}")

    payload = _fetch_vt_resource(resource, normalized, api_key)
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    analysis_stats = attributes.get("last_analysis_stats") or {}
    analysis_results = attributes.get("last_analysis_results") or {}

    return {
        "ioc": normalized,
        "ioc_type": response_type,
        "resource": resource,
        "malicious": analysis_stats.get("malicious", 0),
        "symantec": _extract_vendor_verdict(analysis_results, "Symantec"),
        "mcafeed": _extract_vendor_verdict(analysis_results, "McAfeeD"),
        "stats": analysis_stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
        "reputation": attributes.get("reputation"),
        "tags": attributes.get("tags", []),
        "link": data.get("links", {}).get("self"),
        "raw": data,
    }
