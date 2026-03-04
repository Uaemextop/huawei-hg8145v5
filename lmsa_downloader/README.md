# LMSA Firmware Downloader

A standalone tool that downloads firmware files from `rsddownload-secure.lenovo.com`
using a **fresh GUID + JWT** captured from a running LMSA session.

When the crawler finishes, its JWT session has expired. This tool lets you download
the files again with new credentials captured from HTTPToolkit.

---

## How file downloads work (technical)

Two types of URLs appear in the crawler's output:

| Type | Example | Auth method |
|---|---|---|
| **Direct-auth** | `https://rsddownload-secure.lenovo.com/file.zip` | `Authorization: Bearer <jwt>` + `guid: <guid>` headers |
| **Pre-signed** | `https://rsddownload-secure.lenovo.com/file.zip?X-Amz-Algorithm=…` | Credentials inside the URL — no headers needed |

`download_links.txt` contains **direct-auth** URLs with curl commands that include
the `Authorization` and `guid` headers. The tool parses those headers and **replaces**
the old expired JWT/GUID with the fresh ones from `config.ini`.

---

## Quick start

### Step 1 — Capture fresh GUID + JWT via HTTPToolkit

1. Install [HTTPToolkit](https://httptoolkit.com) (free).
2. Click **Intercept → Software Fix (LMSA)** to start a proxied session.
3. Open any device page in LMSA to trigger an API call.
4. Click any `POST lsa.lenovo.com` request → **Request headers** tab:
   - Copy the `guid` value → paste as `guid` in `config.ini`
   - Copy the `Authorization` value (drop `Bearer ` prefix) → paste as `jwt`
5. *(Optional)* In a `lenovoIdLogin.jhtml` request body, copy `dparams.wust`
   → paste as `wust` in `config.ini` to enable automatic JWT refresh.

### Step 2 — Edit `config.ini`

```ini
[auth]
guid = 3adf1304-8a70-4352-b687-8eddcef6b7d1   ; from HTTPToolkit
jwt  = dcwyMSwoE07AHkME1EQt…                  ; from HTTPToolkit (no "Bearer ")
wust = ZAgAAAAAAAGE9MTM…                       ; optional, enables auto-refresh

[urls]
urls_file = download_links.txt    ; crawler output file

[settings]
output_dir = downloads
workers    = 4
```

### Step 3 — Run

```bash
pip install requests          # one-time setup
python downloader.py          # start downloads
python downloader.py --dry-run   # inspect URLs without downloading
```

---

## Supported URL manifest files

| File | Contents |
|---|---|
| `download_links.txt` | Curl commands with headers — **best option**, headers parsed automatically |
| `lmsa_firmware_urls.txt` | Tab-separated URL + filename (all files) |
| `lmsa_rom_urls.txt` | ROM / OTA firmware only |
| `lmsa_tool_urls.txt` | Flash-tool archives only |
| `lmsa_plugin_urls.txt` | PC-side LMSA plugins |

You can also add URLs inline in `config.ini`:

```ini
[urls]
url_1 = https://rsddownload-secure.lenovo.com/fastboot_lamuc_g_…zip
url_2 = https://download.lenovo.com/lsa/Rescue/…zip
```

---

## Configuration reference

| Section | Key | Default | Description |
|---|---|---|---|
| `[auth]` | `lmsa_jwt` | — | Combined `GUID:JWT` format |
| `[auth]` | `guid` | — | Device GUID (required if lmsa_jwt not set) |
| `[auth]` | `jwt` | — | Bearer token without `Bearer ` prefix (required if lmsa_jwt not set) |
| `[auth]` | `wust` | — | WUST token for JWT auto-refresh (optional) |
| `[auth]` | `base_url` | `https://lsa.lenovo.com/Interface` | LMSA API base URL |
| `[auth]` | `verify_ssl` | `true` | TLS certificate verification |
| `[settings]` | `output_dir` | `downloads` | Output directory |
| `[settings]` | `workers` | `4` | Parallel download threads |
| `[settings]` | `retries` | `3` | Retry count per file |
| `[settings]` | `resume` | `true` | Resume partial downloads |
| `[urls]` | `urls_file` | — | Path to manifest file |
| `[urls]` | `url_N` | — | Inline URL (`url_1`, `url_2`, …) |

---

## JWT expiry

The LMSA JWT rotates on every API call and expires after the session ends.

- If you provide a `wust` token, the tool refreshes the JWT automatically when a
  download returns HTTP 403.
- If you don't have a WUST, capture a new `guid` + `jwt` from HTTPToolkit and
  update `config.ini`.

The WUST itself expires in ~12 hours. After that, open LMSA again and capture
fresh tokens.
