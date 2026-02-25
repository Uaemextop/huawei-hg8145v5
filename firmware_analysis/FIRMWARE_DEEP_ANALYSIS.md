# Deep Firmware Binary Analysis — HG8145V5

> **Firmware**: `5611_HG8145V5V500R020C10SPC212.bin` (21.1 MB)
> **Format**: HWNP multi-section (11 sections)
> **Date**: 2026-02-25
> **Tools**: Capstone ARM disassembler, binwalk, Python3, unsquashfs

## Firmware Structure (HWNP Format)

| # | Section Name | Size | Description |
|---|---|---|---|
| 0 | `file:/var/UpgradeCheck.xml` | 19 KB | Board/chip compatibility XML |
| 1 | `flash:uboot` | 2.5 MB | U-Boot + compressed Linux kernel |
| 2 | `flash:rootfs` | 37.8 MB | SquashFS v4.0 LZMA filesystem |
| 3 | `file:/var/setequiptestmodeoff` | 4 KB | Equipment test mode shell script |
| 4 | `file:/mnt/jffs2/app/plugin_preload.tar.gz` | 7.5 MB | Plugin packages |
| 5 | `file:/var/efs` | 68 B | EFS: `HW MA5600 CHS H801EPBA` |

## U-Boot Analysis

- **Version**: `U-Boot 2020.01 (V500R020C10 V5 - V001)`
- **Console**: `ttyAMA1,115200` (UART)
- **Flash layout**: `startcode → bootpara → flash_configA/B → ubifs → exrootfs → keyfile`
- **Key strings**: `encrypt head decrypt`, `section decrypt`, `export work key`, `get work key`

## Linux Kernel

- **Version**: `Linux 4.4.219`
- **Compiler**: `gcc 7.3.0 (Compiler CPU V200R006C00B010)` — HiSilicon SDK
- **Build**: `Wed Mar 9 20:52:26 CST 2022`
- **Arch**: `SMP ARM` Cortex-A9
- **Load**: `0x80e08000`
- **DTBs**: 14 device tree blobs for sd51xx variants

## SquashFS Rootfs (7004 files, 916 dirs)

### Binary Census

| Category | Count | Key files |
|---|---|---|
| ELF binaries | 799 | ARM 32-bit LE |
| Security-critical | 47+ | aescrypt2, clid, web, httpd |
| Shared libraries | 600+ | /lib/*.so |
| Kernel modules | 80+ | /lib/modules/*.ko |

### Capstone Disassembly Results

#### `bin/aescrypt2` (17,692 bytes, 3 functions)

- **Purpose**: AES-128-CBC file encryption/decryption with HMAC-SHA256
- **Usage**: `aescrypt2 <mode> <input> <output>` (0=encrypt, 1=decrypt)
- **Static key**: `Df7!ui%s9(lmV1L8` at `.rodata:0x307b`
- **Key derivation**: `HW_CTOOL_GetKeyChipStr` → `HW_KMC_CfgGetKey` (hardware)
- The static key is a fallback; actual encryption uses chip-derived keys
- **HMAC verification**: "HMAC check failed: wrong key, or file corrupted"
- **Used for**: `hw_ctree.xml`, SSL certs, Telmex PEM files

#### `bin/clid` (183,008 bytes, 336 functions, 45 security)

- `HW_CLI_VerifySuPassword` @ `0xcc14` (732 bytes)
- `HW_CLI_CheckPwd` @ `0xa7ec` (668 bytes)
- `CLI_AES_GeKey` @ `0xc3bc` (328 bytes) — gets key from XML DB param `0x0B`
- `CLI_AES_Encrypt` @ `0xc504` (708 bytes)
- `CLI_AES_GetRandomStr` @ `0xc90c` (292 bytes)
- `HW_CLI_IfNeedVerifySuPassword` @ `0xcbbc` — checks `FT_SSMP_CLI_SU_CHALLENGE`

#### `lib/libhw_smp_web_base.so` (195,516 bytes, 411 functions, 41 security)

**`HW_WEB_GetSHAByTime` @ `0x186d4` (244 bytes) — ARM disassembly**:

```arm
mov    ip, sp              ; prologue
push   {r4-r8,fp,ip,lr,pc}
mov    r4, r2              ; r4 = output_len parameter
memset(sha_buf, 0, 0x11)   ; 17 bytes (16 hex + null)
memset(hex_buf, 0, 0x41)   ; 65 bytes (64 hex + null)
cmp    r4, #1              ; if output_len <= 1, error
memcpy(sha_buf, input, 17) ; copy date string "YYYYMMDD"
bl     HW_SHA256_CAL       ; SHA-256(date_string)
cmp    r4, #0x41           ; min(output_len, 65)
memcpy(output, hex, len-1) ; copy truncated digest
```

**Confirmed algorithm**: `SHA-256(YYYYMMDD)[:16]`

#### `lib/libhw_smp_web_cfg.so` (95,636 bytes, 172 functions, 16 security)

- `HW_WEB_CheckUserPassword` @ `0x9ccc` (668 bytes)
- `HW_WEB_MkUserPwdByEncryptMode` @ `0xa064` (536 bytes)
- Static key `Df7!ui%s9(lmV1L8` at offset `0x1427e`

#### `lib/libhw_ssp_basic.so` (903,616 bytes, 2334 functions, 261 security)

- AES, SHA-256, PBKDF2, HMAC implementations
- `HW_XML_WebUserInfoSecByIns` @ `0x33a34` — per-user salt generation
- `HW_XML_CFGFileSecurityWithAesKey` @ `0x4ea70`

#### `lib/libhw_web_dll.so` (404,236 bytes, 714 functions, 119 security)

- `HW_WEB_Login` (1924 bytes) — main login
- `HW_WEB_LoginRequestHandle` (2140 bytes)
- `HW_WEB_EncryptPwd` (452 bytes) — dispatch by EncryptMode (0-3)
- `WEB_SecondLogin` (692 bytes) — second-factor

#### `bin/web` (349,876 bytes, 641 functions, 43 security)

- `HW_Web_ChkPassword` (856 bytes)
- `WEB_GetEncryptedKey` (508 bytes)
- `HW_WEB_AIS_CheckUsernameAndPassword` (612 bytes)

## Plugin Packages (plugin_preload.tar.gz)

### eaiapp.ipk (2.7 MB) — AI Traffic Classification

- **MindSpore Lite** neural network for traffic classification
- Binaries: `eaiapp`, `libai_platform.so`, `libsiteai_lite_nn.so`
- Models: `tcp_classify.mslite`, `udp_classify.mslite`
- Rules: `eai_appcfg.csv`, `eai_classifylist.csv` (china/foreign variants)

### kernelapp.cpk (2.1 MB) — Network Plugin

- **MQTT**, **cURL**, **civetweb** (embedded HTTPS), **mbedTLS**
- Binaries: `kernelapp`, `opkg`
- Libraries: `libmbedall.so` (769 crypto functions), `libcurl.so`, `libsrv.so`
- Shell scripts: `plugin_startup_new.sh`, `daemon.sh`, `plugin_monitor.sh`

#### Plugin SSL Certificates

| File | Type | Subject |
|---|---|---|
| `server_ssl.pem` | X.509 cert | CN=ONT-Plugin, O=Huawei |
| `trust_ssl.pem` | X.509 CA cert | CN=HuaWei ONT CA |
| `server_key_ssl.pem` | RSA private key | AES-256-CBC encrypted (PEM) |

#### Plugin Security Functions (from Capstone)

`libsrv.so` (1.8 MB, 12600 strings):
- `ADAPTER_GetRestSslKeyPassword` — SSL key passphrase retrieval
- `ADAPTER_DncryptKeyInfo` / `ADAPTER_EncryptKeyInfo` — key info crypto
- `ADAPTER_SetOntPasswdAuth` — ONT password authentication
- `ADAPTER_SetWebPasswd` — Web password configuration
- `CERT_GetInfoKeypass` / `CERT_EncryKeyPass` — certificate key management
- `POPUP_GetDncryptedSpecKeyInfo` — spec key decryption
- `GPB_InitWebPasswordErrorEvent` — login failure tracking

`libbasic.so` (481 KB):
- `SYSCFG_GetRestSSLkey` — REST API SSL key
- `LOCAL_CheckAccessPassword` — local access auth
- `ADAPTER_SyscmdCheckPasswd` — system command auth

## Certificate & Key Inventory

### Plaintext (extracted)

| File | Type | Subject | Validity |
|---|---|---|---|
| `pub.crt` | X.509 | CN=ont.huawei.com, O=Huawei | 2020-2030 |
| `root.crt` | X.509 CA | CN=Huawei Fixed Network Product CA | 2016-2041 |
| `plugroot.crt` | X.509 CA | CN=HuaWei ONT CA | 2016-2026 |
| `hilink_root.pem` | X.509 CA | CN=root.home (HiLink) | 2014-2024 |
| `su_pub_key` | RSA-256 public | SU challenge verification | — |
| `plugin_server_ssl.pem` | X.509 | CN=ONT-Plugin | 2021-2036 |
| `plugin_trust_ssl.pem` | X.509 CA | CN=HuaWei ONT CA | 2016-2026 |

### Encrypted (PEM — AES-256-CBC passphrase-encrypted)

| File | DEK-Info | Notes |
|---|---|---|
| `prvt.key` | AES-256-CBC, 7EC546FB... | Web SSL private key |
| `plugprvt.key` | AES-256-CBC, 8699C0FB... | Plugin signing key |
| `server_key_ssl.pem` | AES-256-CBC, 17896CEE... | Plugin REST SSL key |

**PEM passphrase**: Derived at runtime by `CERT_GetInfoKeypass` →
`ADAPTER_GetRestSslKeyPassword` from hardware/config. Not a static string.

### Encrypted (aescrypt2 format — chip-derived AES key)

| File | Size | Notes |
|---|---|---|
| `serverkey.pem` | 1800 B | HiLink server key |
| `dropbear_rsa_host_key` | 872 B | SSH host key |

**aescrypt2 key**: `HW_CTOOL_GetKeyChipStr` → `HW_KMC_CfgGetKey` reads a
chip-specific key from hardware. The static `Df7!ui%s9(lmV1L8` is used
only for `hw_ctree.xml` config file encryption, NOT for per-device keys.

### SU Public Key (RSA-256 — CRITICALLY WEAK)

```
Modulus (n): 93047119368797069533900709356153666374682780211774131252649219508533058394837
Exponent (e): 65537
Key size: 256 bits (trivially factorable)
```

This key is used by `HW_CLI_VerifySuPassword` for the CLI `su` challenge.
A 256-bit RSA key can be factored in seconds with proper tools (ECM, QS).

## AES Keys Summary

| Key | Location | Purpose |
|---|---|---|
| `Df7!ui%s9(lmV1L8` | libcfg_api.so, libhw_smp_web_cfg.so, aescrypt2 | hw_ctree.xml encryption, $2 password at-rest |
| `sc189#-_*&1$3cn2` | base_amp_spec.cfg | WiFi quality report AES |
| `0201611041646174` | base_amp_spec.cfg | WiFi quality report IV |
| chip-derived | HW_KMC_CfgGetKey (runtime) | PEM/cert file encryption |

## MEGACABLE Feature Config

```ini
FT_SSMP_PWD_CHALLENGE = 1         # SHA-256 web challenge ENABLED
FT_WLAN_MEGACABLEPWD = 1          # WiFi password customization
FT_SSMP_CLI_SU_CHALLENGE = 0      # CLI SU challenge DISABLED
FT_WEB_HTTPONLY = 1               # HTTPOnly cookies
SSMP_SPEC_WEB_PWDENCRYPT = 3      # PBKDF2-SHA256 mode
SSMP_SPEC_CLI_REMOTETELNET = 1    # Remote telnet enabled
```
