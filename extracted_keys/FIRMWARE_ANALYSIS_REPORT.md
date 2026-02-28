# Huawei ONT Firmware Analysis Report

Consolidated findings from analysis of Huawei HG8145V5, EG8145V5, HG8145C, HN8145XR, and related ONT firmware images.

## Firmware Repositories Analysed

- `firmware-EG8145V5-V500R022C00SPC340B019`
- `firmware-HG8145V5-V500R020C10SPC212`
- `firmware-HG8145C-V5R019C00S105`
- `firmware-HN8145XR-V500R022C10SPC160`
- `firmware-HG8245C-8145C-BLUE-R019-xpon`
- `firmware-HG8145C_17120_ENG`
- `firmware-HG8145V5-V500R020C10SPC212_1`
- `firmware-EG8145V5-V500R022C00SPC340B019_1`
- `firmware-HN8145XR-V500R022C10SPC160_1`
- `firmware-HG8145C-V5R019C00S105_1`
- `firmware-HG8245C-8145C-BLUE-R019-xpon_1`
- `firmware-HG8145C_17120_ENG_1`

## Devices (realfirmware.net)

- Huawei-EG8141A5
- Huawei-EG8145V5
- Huawei-EG8240H5
- Huawei-EG8245H5
- Huawei-HG8145Q2
- Huawei-HG8145V5
- Huawei-HG8145V5V3
- Huawei-HG8145X6
- Huawei-HG8145X6-10
- Huawei-HG8145X7B
- Huawei-HG8245
- Huawei-HG8245A
- Huawei-HG8245H
- Huawei-HG8245H5
- Huawei-HG8245Q
- Huawei-HG8245W5
- Huawei-HG8245W5-6T
- Huawei-HG8246M
- Huawei-HG8247H
- Huawei-HG8247H5
- Huawei-HGONTV500
- Huawei-HS8545M5

## X.509 Certificates

| Path | Description |
|------|-------------|
| `etc/wap/root.crt` | Huawei Equipment CA -> Fixed Network Product CA (2016-2041), SHA256WithRSA, 4096-bit issuer, 2048-bit subject |
| `etc/wap/pub.crt` | ont.huawei.com certificate (2020-2030), SHA256WithRSA, 2048-bit, issued by Fixed Network Product CA |
| `etc/wap/plugroot.crt` | HuaWei ONT CA self-signed root (2016-2026), SHA256WithRSA, 2048-bit, email=support@huawei.com |
| `etc/wap/plugpub.crt` | Plugin signing cert for ont.huawei.com (2017-2067), SHA256WithRSA, 2048-bit, issued by HuaWei ONT CA |
| `etc/app_cert.crt` | Huawei Root CA DER format (2015-2050), binary DER encoded |
| `etc/hilinkcert/root.pem` | root.home self-signed certificate (2014-2024, EXPIRED) |

## Private / Public Keys

### `configs/prvt.key`

- **description**: RSA private key
- **encryption**: AES-256-CBC
- **dek_info**: AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9
- **notes**: Needs Huawei hardware passphrase to decrypt

### `configs/plugprvt.key`

- **description**: RSA private key for plugin signing
- **encryption**: AES-256-CBC
- **dek_info**: AES-256-CBC,8699C0FB1C5FA5FF6A3082AFD6082004
- **notes**: Needs Huawei hardware passphrase to decrypt

### `configs/su_pub_key`

- **description**: RSA-256 bit PUBLIC key (trivially factorable)
- **encryption**: none
- **modulus_hex**: 0xcdb6cdaa1f20dad5
- **exponent**: 65537
- **notes**: Only 256 bits - CRITICALLY WEAK. Can be factored by any modern computer in seconds.

### `configs/dropbear_rsa_host_key`

- **description**: Dropbear SSH host key
- **encryption**: none (binary format)
- **notes**: Binary dropbear key format, shared across devices

## Encryption Keys in Binaries

### aes_config_key

- **value**: Df7!ui%s9(lmV1L8
- **length_bytes**: 16
- **algorithm**: AES-128
- **purpose**: Config file encryption/decryption
- **binary_hits**: 5-18 binaries per firmware image
- **scope**: IDENTICAL across ALL Huawei ONT firmware versions (V300-V500)
- **binaries**: aescrypt2, hw_s_cltcfg, hw_ssp, cfgtool

### su_pub_key_modulus

- **value**: 0xcdb6cdaa...1f20dad5
- **algorithm**: RSA-256
- **purpose**: Firmware signature verification
- **notes**: Trivially factorable by any modern computer

## Firmware Service Accounts (etc/wap/passwd)

### EG8145V5 (V500R022)

- **root**: {'password_field': '*', 'shell': 'nologin'}
- **services**: srv_amp, srv_web, osgi_proxy, srv_igmp, cfg_cwmp, srv_ssmp, cfg_cli, srv_bbsp, srv_dbus, srv_udm, srv_apm, srv_kmc, srv_cms, srv_mu, srv_em, srv_clid, srv_comm, srv_voice, srv_appm, srv_cagent, nobody

### HG8145C (V5R019)

- **root**: {'password_field': 'x', 'shell': 'sh'}
- **osgi**: {'password_field': 'x', 'shell': 'sh'}
- **web**: {'password_field': 'x', 'shell': 'false'}
- **cli**: {'password_field': 'x', 'shell': 'false'}
- **services**: srv_usb, srv_samba, srv_amp, srv_web, osgi_proxy, srv_igmp, cfg_cwmp, srv_ssmp, cfg_omci, cfg_cli, cfg_oam, srv_bbsp, srv_ethoam, srv_dbus, srv_wifi, tool_mu, srv_snmp, srv_apm, tool_iac, nobody, srv_ldsp, srv_voice, srv_appm, srv_user

## Default Credentials

| User | Password | Service | Source |
|------|----------|---------|--------|
| `root` | `admin or adminHW` | Web UI / Telnet | Default factory config |
| `telecomadmin` | `admintelecom` | ISP admin panel | Common ISP default |
| `root` | `root` | Dropbear SSH | Some firmware versions |
| `hw` | `hw` | Telnet diagnostic | Hardware diagnostic mode |

## ISP ACS Credentials

| ISP | ACS URL | Realm | Auth |
|-----|---------|-------|------|
| Telmex | `https://acsvip.megared.net.mx` | HuaweiHomeGateway | HTTP Digest |
| Megacable | `https://acsvip.megared.net.mx` | HuaweiHomeGateway | HTTP Digest |
| Totalplay | `varies by config` | HuaweiHomeGateway | HTTP Digest |
| Claro | `varies by country` | HuaweiHomeGateway | HTTP Digest |

## Encrypted Files

| Path | Description |
|------|-------------|
| `configs/encrypt_spec_key.tar.gz` | Encrypted tar.gz, likely AES encrypted with hardware-derived key |
| `configs/prvt.key` | AES-256-CBC encrypted RSA private key |
| `configs/plugprvt.key` | AES-256-CBC encrypted RSA private key (HG8145C uses DES-EDE3-CBC instead - weaker) |
| `configs/dropbear_rsa_host_key` | Binary dropbear key format |
| `etc/wap/kmc_store_A` | KMC (Key Management Center) keystore, 2592 bytes, only present in 5611 firmware |

## Binary Analysis Highlights

- AES key "Df7!ui%s9(lmV1L8" found as string literal in multiple ARM LE (little-endian) binaries
- TR-069 CWMP: User-Agent=`HuaweiHomeGateway`, realm=`HuaweiHomeGateway`, auth=HTTP Digest
- Other User-Agents: bulk_data=`HW-FTTH`, mac_report=`HW_IPMAC_REPORT`, web_market=`MSIE 9.0`, http_client=`MSIE 8.0`
- Key functions: `ATP_NET_HttpClientCreate`, `HttpBuildPacketHeader`, `HttpClientConnectTo`, `DOWNLOAD_StartDownloadData`
- aescrypt2 tool uses KMC for key management (KMC v3.0.0.B003)
