# Multi-Firmware Exhaustive Analysis

## Firmwares Analyzed

| ID | File | Model | Version | Arch | Kernel | U-Boot | Rootfs |
|----|------|-------|---------|------|--------|--------|--------|
| A | 5611_HG8145V5V500R020C10SPC212.bin | HG8145V5 | V500R020C10SPC212 | ARM LE | Linux 4.4.219 | U-Boot 2020.01 | SquashFS 3197 files |
| B1 | 8145C-V5R019C00S105-EN-BLUE.bin | HG8145C/HG8245C | V500R019C00SPC105 | ARM LE | Linux 3.10.53-HULK2 | U-Boot 2010.03 | SquashFS 3052 files |
| B2 | 8245c-8145c-BLUE-R019-EN-xpon.bin | HG8245C XPON | V500R019C00SPC105B176 | ARM LE | Linux 3.10.53-HULK2 | U-Boot 2010.03 | SquashFS 3130 files |
| B3 | HG8145C_17120_ENG.bin | HG8145C | V300R015C10SPC115 | ARM LE | Linux 3.10.53-HULK2 | N/A | SquashFS 2094 files |
| B4-B6 | Emode/Gmode/Xpon | Config-only | - | - | - | - | 4.9KB HWNP config |
| C | Scun.Firmware.5683 (000.bin) | SmartAX MA5600/5683T | V800R011C00SPC100 | PowerPC BE | VxWorks 6.4/6.8 | N/A | Board EFS firmware |

## HWNP Format Structure

All ONT firmwares use HWNP (Huawei Network Product) container format:
```
Offset 0x00: Magic "HWNP" (4 bytes)
Offset 0x04: Total size (4 bytes BE)
Offset 0x08: CRC32 (4 bytes)
Offset 0x10: Number of sections
Offset 0x20: Board compatibility list (pipe-separated)
```

Scun MA5600 uses "HUAWEI PRODUCT BINARY FILE" container (older VER 1.12 format).

## Certificate/Key Cross-Reference

### Identical Across ALL ONT Firmwares
| File | Type | Notes |
|------|------|-------|
| `su_pub_key` | RSA-256 public key | **IDENTICAL** — Same weak 256-bit RSA key |
| `plugroot.crt` | X.509 CA cert | HuaWei ONT CA, 2048-bit RSA, expires 2026 |
| `hilinkcert/root.pem` | X.509 cert | HiLink root CA, CN=root.home |
| `hilinkcert/servercert.pem` | X.509 cert | HiLink server cert |

### Different Between Firmware Families

| File | HG8145V5 (A) | HG8245C (B1/B2) | HG8145C (B3) |
|------|-------------|-----------------|-------------|
| `prvt.key` | AES-256-CBC,7EC5… | DES-EDE3-CBC,8C0D… | DES-EDE3-CBC,8C0D… (same as B1) |
| `plugprvt.key` | AES-256-CBC,8699… | DES-EDE3-CBC,40BA… | N/A |
| `serverkey.pem` | PEM DES-EDE3-CBC | aescrypt2 binary | aescrypt2 binary |
| `pub.crt` | PEM only (1232B) | X.509 text+PEM (4262B) | X.509 text+PEM (4262B) |
| `root.crt` | Self-signed CA (1703B) | CSR format (1098B) | CSR format (1098B) |
| `plugpub.crt` | 4112B | 4115B | N/A |

**Key finding**: HG8145V5 uses stronger AES-256-CBC for PEM encryption; HG8245C/HG8145C use weaker DES-EDE3-CBC.

### Encryption Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│ KEY 1: Static AES Key (UNIVERSAL)                           │
│ Value: Df7!ui%s9(lmV1L8                                     │
│ Usage: hw_ctree.xml config encryption, CLI su challenge      │
│ Found in: aescrypt2, clid, libhw_ssp_basic.so + 15 others  │
│ IDENTICAL across ALL ONT firmware versions                   │
├─────────────────────────────────────────────────────────────┤
│ KEY 2: PEM Passphrase (HARDWARE-DERIVED)                    │
│ Source: CERT_GetInfoKeypass → ADAPTER_GetRestSslKeyPassword  │
│         → HW_KMC_CfgGetKey → kmc_store_A/kmc_store_B       │
│ Usage: Decrypt prvt.key, plugprvt.key, serverkey.pem        │
│ NOT static — derived from chip-specific KMC store           │
├─────────────────────────────────────────────────────────────┤
│ KEY 3: aescrypt2 File Key (HARDWARE-DERIVED)                │
│ Source: HW_CTOOL_GetKeyChipStr → HW_KMC_CfgGetKey          │
│ Usage: Encrypt/decrypt config files (encrypt_spec.tar.gz)   │
│ Requires: /etc/wap/kmc_store_A, /mnt/jffs2/kmc_store_A     │
└─────────────────────────────────────────────────────────────┘
```

### KMC Store (Key Management Center)
- Version: KMC 3.0.0.B003
- Hardware crypto: disabled (`is hardware crypt[0]`)
- Store files: `kmc_store_A` (2592 bytes), `kmc_store_B` (2592 bytes)
- Only present in HG8145V5 (5611) firmware
- Contains wrapped/encrypted key material, not plaintext keys
- Tool: `/bin/kmc_tool` for key management

## AES Key Distribution

| Firmware | Files containing `Df7!ui%s9(lmV1L8` |
|----------|--------------------------------------|
| HG8145V5 (A) | 18 files: libcfg_api.so, libsmp_api.so, libl3_base.so, libhw_swm_dll.so, libl2_base.so, libhw_ssp_basic.so, libhw_smp_web_cfg.so, libl3_base_api.so, libhw_smp_dm_pdt.so, libhw_voice_sql.so, libl3_ext.so, libhw_smp_psi.so, aescrypt2, app_m, setboardinfo, udm, kmc, clid |
| HG8245C (B1) | 9 files: libhw_smp_web_base.so, libhw_swm_dll.so, libhw_ssp_basic.so, libhw_swm_api.so, libhw_smp_psi.so, aescrypt2, app_m, clid, voice_h248sip |
| HG8245C XPON (B2) | 7 files: libhw_smp_web_base.so, libhw_swm_dll.so, libhw_ssp_basic.so, libhw_smp_psi.so, app_m |
| HG8145C (B3) | 5 files: libhw_smp_web_base.so, libhw_swm_dll.so, libhw_ssp_basic.so, libhw_smp_psi.so, app_m |

## Challenge Password Mechanism

### Web Challenge (HW_WEB_GetSHAByTime)
- **Confirmed in ALL ONT firmwares** via `libhw_smp_web_base.so`
- Symbol: `HW_WEB_GetSHAByTime` at various offsets
- Algorithm: `SHA-256(YYYYMMDD)[:16]` (first 16 hex chars)
- Feature flag: `FT_SSMP_PWD_CHALLENGE`

#### Capstone ARM Disassembly (HG8245C libhw_smp_web_base.so @ 0x24c1c)
```
0x24c1c: mov  ip, sp
0x24c20: mov  r2, #0x41          ; buffer size = 65
0x24c24: push {r4,r5,r6,fp,ip,lr,pc}
0x24c30: mov  r4, #0             ; clear
0x24c38: mov  r5, r1             ; output buffer
0x24c3c: mov  r6, r0             ; date input (YYYYMMDD)
0x24c58: bl   memset             ; clear buffer
0x24c5c: mov  r2, #0x11          ; 17 bytes
0x24c64: mov  r0, r6             ; date string
0x24c68: bl   UInt32ToStr        ; format date → "YYYYMMDD"
0x24c74: bl   SHA256_CAL         ; SHA-256(date_string)
0x24c7c: mov  r1, #0x21          ; 33 bytes output
0x24c84: mov  r3, #0x20          ; 32 bytes hash
0x24c88: bl   strncpy            ; copy first 32 hex chars
0x24c8c: strb r4, [r5, #0x20]   ; null-terminate at position 32
0x24c94: ldm  sp, {r4,r5,r6,fp,sp,pc} ; return
```

### CLI Su Challenge (clid)
- Uses `su_pub_key` (RSA-256) for verification
- Key: `Df7!ui%s9(lmV1L8` stored adjacent to challenge code
- Strings: `"Challenge:"`, `"Make Challenge Fail!"`, `"Please input verification code:"`
- Feature flag: `SSMP_FT_TDE_AUTH_SU_CMD`
- Fallback path: `/mnt/jffs2/su_pub_key` → `/etc/wap/su_pub_key`

### Feature Flags

| Feature | HG8145V5 | HG8245C | HG8245C XPON | HG8145C |
|---------|----------|---------|-------------|---------|
| FT_SSMP_PWD_CHALLENGE | N/A | N/A | N/A | N/A |
| FT_SSMP_CLI_SU_CHALLENGE | N/A | N/A | N/A | N/A |
| FT_WLAN_MEGACABLEPWD | enable=0 | N/A | N/A | N/A |
| FT_SSMP_CTREE_ENCRYPT_KEY | enable=0 | enable=0 | N/A | N/A |
| FT_SSMP_WEB_LOGIN_WITHOUT_PWD | N/A | enable=0 | N/A | N/A |
| FT_SSMP_APP_CHECK_LOGININFO | N/A | enable=1 | N/A | N/A |

## RSA-256 su_pub_key (Shared Across All ONT Firmwares)

```
Modulus (n): 93047119368797069533900709356153666374682780211774131252649219508533058394837
             0xcdb6cda2aa36179aa239fc1d48ce9e82194cc577a631897a2df50dfd1f20dad5
Exponent (e): 65537

Key size: 256 bits — TRIVIALLY FACTORABLE
```

This key is used by `HW_CLI_VerifySuPassword` in `clid` for CLI su challenge authentication.

## SmartAX MA5600/5683T (OLT) Analysis

The Scun firmware is for the ISP-side OLT (Optical Line Terminal), not the ONT.

- **OS**: VxWorks 6.4 (boards) / VxWorks 6.8 (SCUN main control)
- **Architecture**: PowerPC Big-Endian
- **Board**: H801SCUN (main control unit)
- **Content**: 180+ board EFS firmware files for various line cards (GPBD, GPBH, EPBD, etc.)
- **GPON boards**: H806GPBH, H805GPBD, H802GPBD — these manage ONT devices
- **Chip**: SD5120 (ARM) for GPON boards
- **Password**: Console password verification ("Enter Password:", "Invalid Password", "Password Verify OK!")
- **No embedded Linux filesystem** — pure VxWorks RTOS

## Password Generation for Date 20260225

### Web Challenge Password
```python
import hashlib
date_str = "20260225"
sha256_hash = hashlib.sha256(date_str.encode()).hexdigest()
password = sha256_hash[:16]  # First 16 hex characters
# Result: a66e2f879596f119
```

### With SN 4857544347020CB1
The SN is used for config-level operations (ACS, TR-069) but the web challenge
password is date-only: **`a66e2f879596f119`**
