# VirusTotal Vercel Demo

Single query page: `/check_vt`  
Batch xlsx page: `/batch_check_vt`  
AbuseIPDB single query page: `/check_abuseip`  
AbuseIPDB batch xlsx page: `/batch_check_abuseip`  
API paths: `/api/check_vt`, `/api/check_abuseip`

## What these pages do

- `/check_vt`: query one IOC each time and show key fields only.
- `/batch_check_vt`: upload `.xlsx`, batch query row by row, show real-time progress, then download `.xlsx` result.
- `/check_abuseip`: query one IP against AbuseIPDB and show the key fields.
- `/batch_check_abuseip`: upload `.xlsx`, batch query IP rows against AbuseIPDB, skip completed rows, pause/resume, and download `.xlsx` result.
- Template file: `/vt_example.xlsx`

## Batch resume behavior

- Rows with a non-empty `VT_reputation` are treated as completed and skipped on the next run.
- While a batch is running, the page periodically saves the current workbook rows to browser IndexedDB.
- If the same local file is selected again, saved rows are merged back before querying so interrupted runs can resume from blank `VT_reputation` rows.
- The batch page supports pause. Pausing stops assigning new rows, waits for in-flight requests to finish, saves the current result, and enables downloading the partial `.xlsx`.

## Structure

- `public/check_vt.html`: single query page
- `public/batch_check_vt.html`: batch xlsx page
- `public/check_abuseip.html`: AbuseIPDB single IP query page
- `public/batch_check_abuseip.html`: AbuseIPDB batch xlsx page
- `app.py`: Vercel Python entrypoint and API
- `virtual_hash_ip_domain.py`: VT query logic
- `abuseipdb.py`: AbuseIPDB query logic
- `vercel.json`: Vercel routing config

## AbuseIPDB batch columns

Input column matching supports `IP` / `ipAddress` / `ip_address` / `IOC` / `indicator`.

The batch page writes these output columns and skips rows where `Abuse_confidence_score` is already non-empty:

1. `Abuse_confidence_score`
2. `Abuse_country_code`
3. `Abuse_country_name`
4. `Abuse_usage_type`
5. `Abuse_isp`
6. `Abuse_domain`
7. `Abuse_total_reports`
8. `Abuse_num_distinct_users`
9. `Abuse_last_reported_at`
10. `Abuse_is_tor`
11. `Abuse_is_whitelisted`
12. `Abuse_latest_report_comment`

## Template columns

The batch page writes back by column index in this order:

1. `IOC`
2. `Type` (template second column)
3. `SHA256`
4. `VT_reputation`
5. `VT_Sign`
6. `VT_Sign_info`
7. `Autonomous_System_Label`

If any of these 4 output columns are missing (`VT_reputation`, `VT_Sign`, `VT_Sign_info`, `Autonomous_System_Label`), the batch page will auto-create them before query starts.

Input column matching also supports common aliases:
- IOC: `IOC` / `IOC值` / `indicator` / `ioc_value`
- Type: `类型` / `type` / `ioc_type`
- SHA256: `SHA256` / `sha-256` / `sha_256`

## Deploy on Vercel

1. Import this repo into Vercel.
2. Configure VT keys (choose one style below).
3. Redeploy.

### VT key config styles

1. Single key:

- `VT_API_KEY=xxxx`

2. Numbered keys (recommended):

- `VT_API_KEY_1=xxxx`
- `VT_API_KEY_2=xxxx`
- `VT_API_KEY_3=xxxx`
- `VT_API_KEY_4=xxxx`
- Continue with `VT_API_KEY_5...N` when needed.

3. Array/list style:

- `VT_API_KEYS=["key1","key2","key3"]` (JSON array)
- or `VT_API_KEYS=key1,key2,key3` (comma separated)

The backend will merge all configured keys, deduplicate them, rotate the starting key per request, and automatically try the next key when a key returns `429` rate-limit.

### AbuseIPDB key config styles

Use the same pattern as VT, with the `ABUSEIPDB_` prefix:

- `ABUSEIPDB_API_KEY=xxxx`
- `ABUSEIPDB_API_KEY_1=xxxx`
- `ABUSEIPDB_API_KEY_2=xxxx`
- `ABUSEIPDB_API_KEYS=["key1","key2"]`
- or `ABUSEIPDB_API_KEYS=key1,key2`

## Optional proxy

- `VT_PROXY_URL=http://127.0.0.1:7890`
- `ABUSEIPDB_PROXY_URL=http://127.0.0.1:7890` (falls back to `VT_PROXY_URL` when unset)

## API examples

```txt
GET /api/check_vt?ioc=8.8.8.8
GET /api/check_vt?ioc=example.com&type=Domain
GET /api/check_vt?ioc=d41d8cd98f00b204e9800998ecf8427e&type=Hash
GET /api/check_abuseip?ip=118.25.6.39&maxAgeInDays=90
```
