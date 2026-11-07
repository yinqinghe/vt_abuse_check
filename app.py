import json
import os
import re
import threading

from flask import Flask, jsonify, request

from abuseipdb import AbuseIPDBQueryError, query_abuseipdb
from virtual_hash_ip_domain import VTQueryError, query_ioc

app = Flask(__name__)
_key_lock = threading.Lock()
_next_key_index = 0
_next_abuse_key_index = 0


def _enrich_for_template(result: dict) -> dict:
    raw = result.get("raw") or {}
    attributes = raw.get("attributes") or {}
    analysis_results = attributes.get("last_analysis_results") or {}
    analysis_stats = attributes.get("last_analysis_stats") or {}
    ioc_type = (result.get("ioc_type") or "").upper()

    # Keep VT_reputation aligned with legacy logic: malicious hit count.
    result["vt_reputation"] = analysis_stats.get("malicious", result.get("malicious", 0))
    result["sha256"] = attributes.get("sha256")

    if ioc_type == "HASH":
        tags = attributes.get("tags") or []
        normalized_tags = {str(tag).lower() for tag in tags}
        result["vt_sign"] = "signed" if "signed" in normalized_tags else "N"

        signature_info = attributes.get("signature_info")
        if signature_info is None:
            result["vt_sign_info"] = "N"
        elif isinstance(signature_info, (dict, list)):
            result["vt_sign_info"] = json.dumps(signature_info, ensure_ascii=False)
        else:
            result["vt_sign_info"] = str(signature_info)

    elif ioc_type == "IP":
        result["autonomous_system_label"] = attributes.get("as_owner") or "None"

    elif ioc_type == "DOMAIN":
        symantec = analysis_results.get("Symantec") or {}
        mcafeed = analysis_results.get("McAfeeD") or {}
        result["vt_sign"] = "malicious" if symantec.get("category") == "malicious" else "N"
        result["vt_sign_info"] = "malicious" if mcafeed.get("category") == "malicious" else "N"

    return result


def _parse_vt_api_keys(raw: str) -> list[str]:
    text = (raw or "").strip()
    if not text:
        return []

    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]

    return [part.strip() for part in text.split(",") if part.strip()]


def _parse_api_keys(raw: str) -> list[str]:
    return _parse_vt_api_keys(raw)


def _load_all_vt_api_keys() -> list[str]:
    keys: list[str] = []
    keys.extend(_parse_vt_api_keys(os.getenv("VT_API_KEYS", "")))

    single_key = os.getenv("VT_API_KEY", "").strip()
    if single_key:
        keys.append(single_key)

    numbered_keys: list[tuple[int, str]] = []
    pattern = re.compile(r"^VT_API_KEY_(\d+)$")
    for env_name, env_value in os.environ.items():
        match = pattern.match(env_name)
        if not match:
            continue
        value = (env_value or "").strip()
        if not value:
            continue
        numbered_keys.append((int(match.group(1)), value))

    for _, value in sorted(numbered_keys, key=lambda item: item[0]):
        keys.append(value)

    deduped: list[str] = []
    seen = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    return deduped


def _load_all_abuseipdb_api_keys() -> list[str]:
    keys: list[str] = []
    keys.extend(_parse_api_keys(os.getenv("ABUSEIPDB_API_KEYS", "")))

    single_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if single_key:
        keys.append(single_key)

    numbered_keys: list[tuple[int, str]] = []
    pattern = re.compile(r"^ABUSEIPDB_API_KEY_(\d+)$")
    for env_name, env_value in os.environ.items():
        match = pattern.match(env_name)
        if not match:
            continue
        value = (env_value or "").strip()
        if not value:
            continue
        numbered_keys.append((int(match.group(1)), value))

    for _, value in sorted(numbered_keys, key=lambda item: item[0]):
        keys.append(value)

    deduped: list[str] = []
    seen = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    return deduped


def _rotate_keys(keys: list[str]) -> list[str]:
    if not keys:
        return []

    global _next_key_index
    with _key_lock:
        start = _next_key_index % len(keys)
        _next_key_index = (_next_key_index + 1) % len(keys)
    return keys[start:] + keys[:start]


def _rotate_abuse_keys(keys: list[str]) -> list[str]:
    if not keys:
        return []

    global _next_abuse_key_index
    with _key_lock:
        start = _next_abuse_key_index % len(keys)
        _next_abuse_key_index = (_next_abuse_key_index + 1) % len(keys)
    return keys[start:] + keys[:start]


@app.get("/api/check_vt")
def check_vt():
    ioc = (request.args.get("ioc") or "").strip()
    ioc_type = (request.args.get("type") or "").strip() or None

    if not ioc:
        return jsonify({"error": "missing ioc parameter"}), 400

    api_keys = _rotate_keys(_load_all_vt_api_keys())
    if not api_keys:
        return (
            jsonify(
                {
                    "error": "missing VT API keys, set VT_API_KEY or VT_API_KEYS or VT_API_KEY_1..N"
                }
            ),
            500,
        )

    last_exc: Exception | None = None
    for index, api_key in enumerate(api_keys):
        try:
            result = query_ioc(ioc=ioc, api_key=api_key, ioc_type=ioc_type)
            result = _enrich_for_template(result)
            result["used_key_slot"] = index + 1
            result["key_pool_size"] = len(api_keys)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except VTQueryError as exc:
            last_exc = exc
            if exc.status_code == 429 and index < len(api_keys) - 1:
                continue
            if exc.status_code == 429:
                return jsonify({"error": str(exc), "detail": "all keys are rate limited"}), 429
            return jsonify({"error": str(exc)}), 502
        except RuntimeError as exc:
            last_exc = exc
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:
            last_exc = exc
            break

    return jsonify({"error": "server query failed", "detail": str(last_exc) if last_exc else None}), 500


@app.get("/api/check_abuseip")
def check_abuseip():
    ip_address = (request.args.get("ip") or request.args.get("ipAddress") or "").strip()
    max_age_raw = (request.args.get("maxAgeInDays") or "90").strip()

    if not ip_address:
        return jsonify({"error": "missing ip parameter"}), 400

    try:
        max_age = int(max_age_raw)
    except ValueError:
        return jsonify({"error": "maxAgeInDays must be an integer"}), 400

    api_keys = _rotate_abuse_keys(_load_all_abuseipdb_api_keys())
    if not api_keys:
        return (
            jsonify(
                {
                    "error": "missing AbuseIPDB API keys, set ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEYS or ABUSEIPDB_API_KEY_1..N"
                }
            ),
            500,
        )

    last_exc: Exception | None = None
    for index, api_key in enumerate(api_keys):
        try:
            result = query_abuseipdb(ip_address=ip_address, api_key=api_key, max_age_in_days=max_age)
            result["used_key_slot"] = index + 1
            result["key_pool_size"] = len(api_keys)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except AbuseIPDBQueryError as exc:
            last_exc = exc
            if exc.status_code == 429 and index < len(api_keys) - 1:
                continue
            if exc.status_code == 429:
                return jsonify({"error": str(exc), "detail": "all keys are rate limited"}), 429
            return jsonify({"error": str(exc)}), 502
        except RuntimeError as exc:
            last_exc = exc
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:
            last_exc = exc
            break

    return jsonify({"error": "server query failed", "detail": str(last_exc) if last_exc else None}), 500
