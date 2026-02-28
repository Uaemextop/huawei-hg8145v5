# Firmware Analysis Report - Extracted Keys, Certificates & Credentials

Generated: 2026-02-28 19:00:06 UTC
Source: Uaemextop/realfirmware-net (branch: copilot/extract-and-organize-compressed-files)

---

## Table of Contents

1. [Firmware Files Analyzed](#firmware-files-analyzed)
2. [Private Keys](#private-keys)
3. [Certificates](#certificates)
4. [Public Keys](#public-keys)
5. [Default Credentials](#default-credentials)
6. [AES Encryption Key](#aes-encryption-key)
7. [Capstone Binary Analysis](#capstone-binary-analysis)
8. [Encrypted Files](#encrypted-files)

---

## Firmware Files Analyzed

| File | Size | Format |
|------|------|--------|
| firmware/Huawei-HG8145X6-10/Totalplay/TOTAL.bin | 45.8 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8145V5V3/Telmex/V2.bin | 1.7 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245/General/HG8245 common ok.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/ZTE-F660/General/F660_H248_V2.30.62P2T1_UPGRADE_BOOTLDR.bin | 10.5 MB | RAR archive |
| firmware/Ping-7962V1/Telmex/FOlt.bin | 13.7 MB | FWU package |
| firmware/Huawei-HG8245W5-6T/General/HG8245W5 T6-COMMON-OK.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245W5-6T/General/unlock_1.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245W5-6T/General/shell.bin | 1.8 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245W5-6T/Personal-Paraguay/R020.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245W5-6T/Claro-Argentina/HG  G40.bin | 0.2 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245W5-6T/Claro-Argentina/unlock.bin | 0.2 MB | HWNP (Huawei encrypted) |
| firmware/ZTE-F670L/General/F670L_V1.1.20P3N4D_UPGRADE_BOOTLDR.bin | 19.2 MB | ZTE encrypted |
| firmware/ZTE-F670L/General/F670L_V1.1.20P1N55.bin | 19.0 MB | ZTE encrypted |
| firmware/ZTE-F670L/Telmex/respaldo.bin | 0.0 MB | unknown (04030201) |
| firmware/ZTE-F670L/Telmex/upgrade.bin | 23.6 MB | ZTE encrypted |
| firmware/ZTE-F670L/Airtel-India/F670L_V9..bin | 23.0 MB | ZTE encrypted |
| firmware/Huawei-HGONTV500/Claro-Dominicana/HGONTV500.bin | 46.4 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245A/Conversion-XPON/HG8245A XPON.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/ZTE-F680/CNT-Ecuador/F680_V6.0..bin | 20.3 MB | ZTE encrypted |
| firmware/Huawei-HG8145V5/Conversion-XPON/HG8145V5-XPON.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8145V5/General/HG8145V5-.bin | 47.9 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8145V5/Totalplay/Total G150.bin | 36.9 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8145V5/Conversion-EPON/HG8145V5-R019-EPON.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8145V5/Safaricom/STEP 1 HG8145V.bin | 36.8 MB | HWNP (Huawei encrypted) |
| firmware/ZTE-F660E/ETB-Colombia/ZTE F660E.bin | 20.0 MB | ZTE encrypted |
| firmware/Huawei-HG8247H/Vodafone/HG8247H UPGRADE.bin | 26.2 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245Q/General/HG8245Q SUBIR UPGRADE.bin | 27.2 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245H/Conversion-XPON/HG8245H XPON.bin | 0.7 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245H/General/HG8245H-COMMON-OK.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245H/Conversion-EPON/HG8245H EPON.bin | 0.0 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8246M/Conversion-XPON/HG8546M XPON.bin | 0.2 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8246M/General/Firmware HG8246M TO V5.bin | 28.9 MB | HWNP (Huawei encrypted) |
| firmware/Huawei-HG8245H5/Conversion-EPON/HG8245H5 EPON.bin | 0.2 MB | HWNP (Huawei encrypted) |
| firmware/GX-Earth-2022/General/earth-2022-E2022-2.1.1-R.img | 12.6 MB | disk image |
| firmware/GX-Earth-4222/General/earth-4222-E4222-2.0.7-R.img | 13.7 MB | disk image |

---

## Private Keys

### plugprvt.key
- **File**: `etc/wap/plugprvt.key`
- **Type**: encrypted_private_key
- **Size**: 1765 bytes

### prvt.key
- **File**: `etc/wap/prvt.key`
- **Type**: encrypted_private_key
- **Size**: 1765 bytes

### dropbear_rsa_host_key
- **File**: `etc/dropbear/dropbear_rsa_host_key`
- **Type**: dropbear_rsa_host_key
- **Size**: 872 bytes

### prvt_1_totalplay.pem
- **File**: `etc/wap/cert/prvt_1_totalplay.pem`
- **Type**: encrypted_private_key
- **Size**: 962 bytes

### prvt_1_telmex.pem
- **File**: `etc/wap/cert/prvt_1_telmex.pem`
- **Type**: encrypted_private_key
- **Size**: 985 bytes

### plugprvt.key
- **File**: `etc/wap/plugprvt.key`
- **Type**: encrypted_private_key
- **Size**: 1765 bytes

### prvt.key
- **File**: `etc/wap/prvt.key`
- **Type**: encrypted_private_key
- **Size**: 1833 bytes

### dropbear_rsa_host_key
- **File**: `etc/dropbear/dropbear_rsa_host_key`
- **Type**: dropbear_rsa_host_key
- **Size**: 872 bytes

### plugprvt.key
- **File**: `etc/wap/plugprvt.key`
- **Type**: encrypted_private_key
- **Size**: 1742 bytes

### prvt.key
- **File**: `etc/wap/prvt.key`
- **Type**: encrypted_private_key
- **Size**: 1750 bytes

### dropbear_rsa_host_key
- **File**: `etc/dropbear/dropbear_rsa_host_key`
- **Type**: dropbear_rsa_host_key
- **Size**: 872 bytes

### plugprvt.key
- **File**: `etc/wap/plugprvt.key`
- **Type**: encrypted_private_key
- **Size**: 1742 bytes

### prvt.key
- **File**: `etc/wap/prvt.key`
- **Type**: encrypted_private_key
- **Size**: 1750 bytes

### dropbear_rsa_host_key
- **File**: `etc/dropbear/dropbear_rsa_host_key`
- **Type**: dropbear_rsa_host_key
- **Size**: 872 bytes

### client.pem
- **File**: `etc/client.pem`
- **Type**: encrypted_private_key
- **Size**: 962 bytes

### ssl_key.pem
- **File**: `etc/ssl_key.pem`
- **Type**: private_key
- **Size**: 1678 bytes

### client.pem
- **File**: `etc/client.pem`
- **Type**: encrypted_private_key
- **Size**: 962 bytes

### ssl_key.pem
- **File**: `etc/ssl_key.pem`
- **Type**: private_key
- **Size**: 1678 bytes

### ssl_key.pem
- **File**: `etc/ssl_key.pem`
- **Type**: private_key
- **Size**: 1678 bytes

---

## Certificates

### servercert.pem
- **File**: `etc/wap/hilinkcert/servercert.pem`
- **Type**: certificate
- **Size**: 1455 bytes

### root.pem
- **File**: `etc/wap/hilinkcert/root.pem`
- **Type**: certificate
- **Size**: 1329 bytes

### plugroot.crt
- **File**: `etc/wap/plugroot.crt`
- **Type**: certificate
- **Size**: 1288 bytes

### pub.crt
- **File**: `etc/wap/pub.crt`
- **Type**: certificate
- **Size**: 1232 bytes

### root.crt
- **File**: `etc/wap/root.crt`
- **Type**: certificate
- **Size**: 1703 bytes

### plugpub.crt
- **File**: `etc/wap/plugpub.crt`
- **Type**: certificate
- **Size**: 1268 bytes

### root_1_totalplay.pem
- **File**: `etc/wap/cert/root_1_totalplay.pem`
- **Type**: certificate
- **Size**: 1138 bytes

### pub_1_totalplay.pem
- **File**: `etc/wap/cert/pub_1_totalplay.pem`
- **Type**: certificate
- **Size**: 907 bytes

### pub_1_telmex.pem
- **File**: `etc/wap/cert/pub_1_telmex.pem`
- **Type**: certificate
- **Size**: 1207 bytes

### root_1_telmex.pem
- **File**: `etc/wap/cert/root_1_telmex.pem`
- **Type**: certificate
- **Size**: 1284 bytes

### servercert.pem
- **File**: `etc/wap/hilinkcert/servercert.pem`
- **Type**: certificate
- **Size**: 1455 bytes

### root.pem
- **File**: `etc/wap/hilinkcert/root.pem`
- **Type**: certificate
- **Size**: 1329 bytes

### plugroot.crt
- **File**: `etc/wap/plugroot.crt`
- **Type**: certificate
- **Size**: 1288 bytes

### pub.crt
- **File**: `etc/wap/pub.crt`
- **Type**: certificate
- **Size**: 1353 bytes

### root.crt
- **File**: `etc/wap/root.crt`
- **Type**: certificate
- **Size**: 1349 bytes

### plugpub.crt
- **File**: `etc/wap/plugpub.crt`
- **Type**: certificate
- **Size**: 1268 bytes

### servercert.pem
- **File**: `etc/wap/hilinkcert/servercert.pem`
- **Type**: certificate
- **Size**: 1455 bytes

### root.pem
- **File**: `etc/wap/hilinkcert/root.pem`
- **Type**: certificate
- **Size**: 1329 bytes

### plugroot.crt
- **File**: `etc/wap/plugroot.crt`
- **Type**: certificate
- **Size**: 1288 bytes

### pub.crt
- **File**: `etc/wap/pub.crt`
- **Type**: certificate
- **Size**: 1353 bytes

### plugpub.crt
- **File**: `etc/wap/plugpub.crt`
- **Type**: certificate
- **Size**: 1268 bytes

### servercert.pem
- **File**: `etc/wap/hilinkcert/servercert.pem`
- **Type**: certificate
- **Size**: 1455 bytes

### root.pem
- **File**: `etc/wap/hilinkcert/root.pem`
- **Type**: certificate
- **Size**: 1329 bytes

### plugroot.crt
- **File**: `etc/wap/plugroot.crt`
- **Type**: certificate
- **Size**: 1288 bytes

### pub.crt
- **File**: `etc/wap/pub.crt`
- **Type**: certificate
- **Size**: 1353 bytes

### plugpub.crt
- **File**: `etc/wap/plugpub.crt`
- **Type**: certificate
- **Size**: 1268 bytes

### ssl_cert.pem
- **File**: `etc/ssl_cert.pem`
- **Type**: certificate
- **Size**: 1622 bytes

### cacert.pem
- **File**: `etc/cacert.pem`
- **Type**: certificate
- **Size**: 1272 bytes

### client.pem
- **File**: `etc/client.pem`
- **Type**: certificate
- **Size**: 1288 bytes

### client.pem
- **File**: `etc/client.pem`
- **Type**: certificate
- **Size**: 1272 bytes

### ssl_cert.pem
- **File**: `etc/ssl_cert.pem`
- **Type**: certificate
- **Size**: 1622 bytes

### cacert.pem
- **File**: `etc/cacert.pem`
- **Type**: certificate
- **Size**: 1272 bytes

### client.pem
- **File**: `etc/client.pem`
- **Type**: certificate
- **Size**: 1288 bytes

### client.pem
- **File**: `etc/client.pem`
- **Type**: certificate
- **Size**: 1272 bytes

### ssl_cert.pem
- **File**: `etc/ssl_cert.pem`
- **Type**: certificate
- **Size**: 1622 bytes

---

## Public Keys

### su_pub_key
- **File**: `etc/wap/su_pub_key`
- **Type**: rsa_256_public_key
- **Note**: Trivially factorable RSA-256 key

### su_pub_key
- **File**: `etc/wap/su_pub_key`
- **Type**: rsa_256_public_key
- **Note**: Trivially factorable RSA-256 key

### su_pub_key
- **File**: `etc/wap/su_pub_key`
- **Type**: rsa_256_public_key
- **Note**: Trivially factorable RSA-256 key

### su_pub_key
- **File**: `etc/wap/su_pub_key`
- **Type**: rsa_256_public_key
- **Note**: Trivially factorable RSA-256 key

---

## Default Credentials

| Device | User | Password | Context |
|--------|------|----------|---------|
| Huawei-HG8145V5 | `telecomadmin` | `admintelecom` | Super user default |
| Huawei-HG8145V5 | `root` | `admin` | Telnet/SSH access |
| Huawei-HG8145V5 | `telecomadmin` | `F0xB734Fr3@j%YEP` | Totalplay super user |
| Huawei-HG8145V5 | `root` | `adminHW` | Totalplay telnet |
| Huawei-HG8145V5V3 | `root` | `admin` | Telnet access |
| Huawei-HGONTV500 | `CLARO` | `T3L3C0MCL4R0!` | Claro Dominicana ISP user |
| Huawei-HGONTV500 | `LCDaTOSCOR` | `me@jrUywiqW+LW*W` | Claro super user |
| ATW-662G | `TELMEX` | `Nm4Pm2Cc3u` | Telmex ISP user |
| ATW-662G | `admin` | `NuCom` | Default after reset |
| ZTE-F660 | `root` | `admin` | Telnet access via zte_telnet.exe |
| ZTE-F670L | `admin` | `Web@0063` | Default web interface |
| ZTE-F680 | `admin` | `1pl4n422ZTE2014.!` | Iplan Argentina |
| ZTE-F680 | `admin` | `Web@0063` | Default web interface |
| ZTE-F660-Totalplay | `WBmew6JF` | `zGe8qHTy` | FactoryMode telnet auth |

### Credentials Found in Documents

- **documents/Huawei-HG8145X6-10/Totalplay/INF_1.txt**

- **documents/Nokia-G1425G-A/General/apoyo manual.txt**

- **documents/General/Totalplay/solucion desbloqueo totalplay version r021.txt**

- **documents/General/Claro-Dominicana/PASOS.txt**

- **documents/Nokia-G2425G-A/ETB-Colombia/apoyo manual.txt**

- **documents/Nokia-G2425G-A/Airtel-India/note.txt**

- **documents/Nokia-G2425G-A/Airtel-India/note_1.txt**

- **documents/Nokia-G2425G-A/Airtel-India/note_2.txt**

- **documents/Nokia-G2425G-A/Airtel-India/Note.txt**

- **documents/Nokia-G2425G-A/Airtel-India/note_3.txt**

- **documents/Huawei-HG8145V5V3/General/inf gpon.txt**

- **documents/Huawei-HG8145V5V3/Telmex/inf Epon.txt**

- **documents/Huawei-HG8245/General/inf.txt**

- **documents/ZTE-F660/General/inf.txt**

- **documents/ZTE-F660/Totalplay/pasos .txt**

- **documents/ZTE-F660/Totalplay/user.txt**

- **documents/Alcatel-G240W-B/General/apoyo manual.txt**

- **documents/ATW-662G/General/inf_2.txt**

- **documents/ATW-662G/Telmex/inf.txt**

- **documents/ATW-662G/Telmex/inf_1.txt**

- **documents/Ping-7962V1/Telmex/inf.txt**

- **documents/Huawei-HG8245W5-6T/General/INF.txt**

- **documents/ZTE-F670L/Telmex/user.txt**

- **documents/Nokia-G2425G-B/Personal-Paraguay/inf.txt**

- **documents/Huawei-HG8145V5/General/PASSO.txt**

- **documents/Huawei-HG8145V5/Totalplay/pasos_4.txt**

- **documents/Huawei-HG8145V5/Safaricom/INF.txt**

- **documents/Huawei-HG8145V5/Claro-Dominicana/pasos_2.txt**

- **documents/Huawei-HG8145V5/Viettel-Vietnam/inf.txt**

- **documents/Huawei-HG8245W5/Polonia/IF.txt**

---

## AES Encryption Key

The following AES-256 key is embedded in multiple firmware binaries across
all Huawei ONT devices (HG8145V5, HG8245H, HG8246M, HG8247H, HGONTV500):

```
Key: Df7!ui%s9(lmV1L8
Algorithm: AES-256-CBC
Usage: Configuration encryption, firmware component encryption
```

### Binaries containing the AES key:

- `bin/aescrypt2` - AES encryption utility
- `lib/libhw_smp_dm_pdt.so` - Device management library
- `lib/libsmp_api.so` - SMP API library
- `lib/libl3_base_api.so` - L3 base API
- `lib/libl2_base.so` - L2 base library
- `lib/libhw_ssp_basic.so` - SSP basic library
- `lib/libl3_ext.so` - L3 extension library
- `lib/libcfg_api.so` - Config API library
- `lib/libhw_voice_sql.so` - Voice SQL library
- `lib/libhw_smp_web_cfg.so` - Web config library

### RSA-256 su_pub_key (trivially factorable):

```
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM22zaKqNheaojn8HUjOnoIZTMV3pjGJ
ei31Df0fINrVAgMBAAE=
-----END PUBLIC KEY-----
```

This RSA key is only 256 bits, making it trivially factorable.
It is used for super-user authentication across all Huawei ONT firmwares.

---

## Capstone Binary Analysis

### libl3_base_api.so
- **Architecture**: ARM
- **Size**: 173108 bytes
- **Key Found**: AES-256 at offset 0x25bf7
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x5558
- **Disassembly around key**:
  ```asm
  0x00025bb7: ldrbpl	r4, [r0, #-0x300]
  0x00025bbb: svcpl	#0x534f51
  0x00025bbf: subshs	r4, r8, sp, asr #2
  0x00025bc3: andeq	r6, sl, r5, lsr #8
  0x00025bc7: subspl	r4, r3, r2, asr #4
  0x00025bcb: ldrbmi	r5, [r0, #-0x35f]
  0x00025bcf: subpl	r5, r3, r3, asr #30
  0x00025bd3: movtpl	r5, #0xf155
  0x00025bd7: ldrtmi	r4, [r3], #-0xc5f
  0x00025bdb: strbpl	r4, [r1, #-0x645]
  ```

### libsmp_api.so
- **Architecture**: ARM
- **Size**: 324796 bytes
- **Key Found**: AES-256 at offset 0x475ad
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x888a
  - `aes_encrypt` at 0x88d6
- **Disassembly around key**:
  ```asm
  0x0004756d: stclvs	p5, c2, [ip], #-0x80
  0x00047571: stcvs	p0, c2, [r5], #-0x1d4
  0x00047575: strhs	r7, [r0, #-0x56c]!
  0x00047579: rsbseq	r6, r5, ip, ror #24
  0x0004757d: rsbseq	r7, r5, r3, rrx
  0x00047581: svcvs	#0x507055
  0x00047585: ldrhs	r7, [sl, #-0x472]!
  0x00047589: andeq	r0, sl, r4, ror #26
  0x0004758d: subpl	r5, sp, r3, asr r3
  0x00047591: ldrbmi	r5, [r0, #-0x35f]
  ```

### aescrypt2
- **Architecture**: ARM
- **Size**: 17692 bytes
- **Key Found**: AES-256 at offset 0x307b
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Disassembly around key**:
  ```asm
  0x0000303b: stclt	p5, c13, [fp], {0x84}
  0x0000303f: ldcvc	p2, c6, [r6, #0x268]
  ```

### kmc
- **Architecture**: ARM
- **Size**: 34180 bytes
- **Key Found**: AES-256 at offset 0x67d0
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x149a
- **Disassembly around key**:
  ```asm
  0x00006790: svcpl	#0x434d4b
  0x00006794: stmdbvs	r4!, {r0, r2, r3, r6, r8, sb, sl, fp, sp, lr} ^
  0x00006798: blmi	#0x1364d38
  0x0000679c: strbvs	r6, [sp, #-0x954]!
  ```

### app_m
- **Architecture**: ARM
- **Size**: 347296 bytes
- **Key Found**: AES-256 at offset 0x485a8
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x52cc
  - `aes_encrypt` at 0x6e1a
- **Disassembly around key**:
  ```asm
  0x00048568: strbvs	r5, [r5, -r4, ror #4]!
  0x0004856c: blo	#0x1d65318
  0x00048570: eorhs	r6, ip, r5, lsr #8
  0x00048574: strbvs	r7, [lr, #-0x349]
  0x00048578: ldrbvs	r6, [r2, #-0x465]
  0x0004857c: ldclmi	p5, c6, [r4], #-0x1cc
  0x00048580: stclvs	p3, c6, [r1], #-0x1bc
  0x00048584: stcleq	p5, c2, [r4, #-0xe8]!
  0x00048588: stcvs	p0, c0, [pc, #-0x28]!
  0x0004858c: bvs	#0xc2574c
  ```

### clid
- **Architecture**: ARM
- **Size**: 183008 bytes
- **Key Found**: AES-256 at offset 0x2740d
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `password_ref` at 0x28a40
  - `aes_decrypt` at 0x4863
- **Disassembly around key**:
  ```asm
  0x000273cd: strbpl	r5, [r1, #-0xf45]
  0x000273d1: cmppl	pc, #84, #16
  0x000273d5: stclmi	p15, c5, [r3, #-0x154]
  0x000273d9: ldrbvc	r0, [r3, #-0x44]!
  0x000273dd: cdpvs	p15, #6, c2, c13, c0, #0
  0x000273e1: uqsub16vs	r2, sl, r4
  0x000273e5: svchs	#0x327366
  0x000273e9: subsvc	r7, pc, r3, ror r5
  0x000273ed: blvs	#0x17ffdc9
  0x000273f1: svchs	#0x7965
  ```

### libsmp_api.so
- **Architecture**: ARM
- **Size**: 311112 bytes
- **Key Found**: AES-256 at offset 0x43cbf
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x8273
  - `aes_encrypt` at 0x82ae
- **Disassembly around key**:
  ```asm
  0x00043c7f: stclvs	p5, c2, [ip], #-0x80
  0x00043c83: stcvs	p0, c2, [r5], #-0x1d4
  0x00043c87: strhs	r7, [r0, #-0x56c]!
  0x00043c8b: rsbseq	r6, r5, ip, ror #24
  0x00043c8f: rsbseq	r7, r5, r3, rrx
  0x00043c93: svcvs	#0x507055
  0x00043c97: ldrhs	r7, [sl, #-0x472]!
  0x00043c9b: andeq	r0, sl, r4, ror #26
  0x00043c9f: subpl	r5, sp, r3, asr r3
  0x00043ca3: ldrbmi	r5, [r0, #-0x35f]
  ```

### aescrypt2
- **Architecture**: ARM
- **Size**: 17912 bytes
- **Key Found**: AES-256 at offset 0x308f
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Disassembly around key**:
  ```asm
  0x0000304f: stclt	p5, c13, [fp], {0x84}
  0x00003053: ldcvc	p2, c6, [r6, #0x268]
  ```

### kmc
- **Architecture**: ARM
- **Size**: 30432 bytes
- **Key Found**: AES-256 at offset 0x6768
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x1340
- **Disassembly around key**:
  ```asm
  0x00006728: svcpl	#0x434d4b
  0x0000672c: stmdbvs	r4!, {r0, r2, r3, r6, r8, sb, sl, fp, sp, lr} ^
  0x00006730: blmi	#0x1364cd0
  0x00006734: strbvs	r6, [sp, #-0x954]!
  ```

### app_m
- **Architecture**: ARM
- **Size**: 408140 bytes
- **Key Found**: AES-256 at offset 0x55352
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x6b20
  - `aes_encrypt` at 0x764a
- **Disassembly around key**:
  ```asm
  0x00055312: strbvs	r5, [r5, -r4, ror #4]!
  0x00055316: blo	#0x1d720c2
  0x0005531a: eorhs	r6, ip, r5, lsr #8
  0x0005531e: strbvs	r7, [lr, #-0x349]
  0x00055322: ldrbvs	r6, [r2, #-0x465]
  0x00055326: ldclmi	p5, c6, [r4], #-0x1cc
  0x0005532a: stclvs	p3, c6, [r1], #-0x1bc
  0x0005532e: stcleq	p5, c2, [r4, #-0xe8]!
  0x00055332: stcvs	p0, c0, [pc, #-0x28]!
  0x00055336: bvs	#0xc324f6
  ```

### clid
- **Architecture**: ARM
- **Size**: 184192 bytes
- **Key Found**: AES-256 at offset 0x291b3
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `password_ref` at 0x27ce8
  - `aes_decrypt` at 0x53e2
- **Disassembly around key**:
  ```asm
  0x00029173: strbpl	r5, [r1, #-0xf45]
  0x00029177: cmppl	pc, #84, #16
  0x0002917b: stclmi	p15, c5, [r3, #-0x154]
  0x0002917f: ldrbvc	r0, [r3, #-0x44]!
  0x00029183: cdpvs	p15, #6, c2, c13, c0, #0
  0x00029187: uqsub16vs	r2, sl, r4
  0x0002918b: svchs	#0x327366
  0x0002918f: subsvc	r7, pc, r3, ror r5
  0x00029193: blvs	#0x1801b6f
  0x00029197: svchs	#0x7965
  ```

### clid
- **Architecture**: ARM
- **Size**: 163472 bytes
- **Key Found**: AES-256 at offset 0x24e20
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `password_ref` at 0x243e8
  - `aes_decrypt` at 0x41ff
- **Disassembly around key**:
  ```asm
  0x00024de0: svcpl	#0x55535f
  0x00024de4: subeq	r4, r4, r3, asr #26
  0x00024de8: andeq	r7, r0, r3, ror r5
  0x00024dec: strbtvc	r6, [lr], #-0xd2f
  0x00024df0: strbtvs	r6, [r6], -pc, lsr #20
  ```

### app_m
- **Architecture**: ARM
- **Size**: 308464 bytes
- **Key Found**: AES-256 at offset 0x40069
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `aes_decrypt` at 0x3b5b
  - `aes_encrypt` at 0x45fe
- **Disassembly around key**:
  ```asm
  0x00040029: ldclmi	p0, c5, [pc, #-0x140]
  0x0004002d: stclvs	p2, c5, [r5, #-0x17c]!
  0x00040031: stclmi	p4, c7, [r5, #-0x1bc]!
  0x00040035: strbvs	r6, [r1, -r1, ror #28]!
  0x00040039: ldrbvs	r5, [r3, #-0xf65]
  0x0004003d: cmnvs	r0, #116, #4
  0x00040041: vaddmi.f16	s9, s6, s1
  0x00040045: rsbpl	r6, r4, #0x19400000
  ```

### clid
- **Architecture**: ARM
- **Size**: 163432 bytes
- **Key Found**: AES-256 at offset 0x24a60
  - Value: `Df7!ui%s9(lmV1L8`
  - Context: Huawei firmware encryption key
- **Strings of interest**:
  - `password_ref` at 0x2402c
  - `aes_decrypt` at 0x41c8
- **Disassembly around key**:
  ```asm
  0x00024a20: svcpl	#0x55535f
  0x00024a24: subeq	r4, r4, r3, asr #26
  0x00024a28: andeq	r7, r0, r3, ror r5
  0x00024a2c: strbtvc	r6, [lr], #-0xd2f
  0x00024a30: strbtvs	r6, [r6], -pc, lsr #20
  ```

---

## Encrypted Files

### HWNP Encrypted Firmware

All Huawei `.bin` firmware files use the HWNP format, which includes:
- HWNP header with product IDs and version info
- Encrypted firmware payload
- Contains: Linux kernel (uImage), Squashfs root filesystem, device trees

### Private Key Encryption

- `prvt.key` - AES-256-CBC encrypted RSA private key (needs HW passphrase)
- `plugprvt.key` - AES-256-CBC encrypted RSA plugin private key
- `prvt_1_telmex.pem` - AES-256-CBC encrypted (Telmex ISP key)
- `prvt_1_totalplay.pem` - DES-EDE3-CBC encrypted (Totalplay ISP key, weaker)

### KMC Key Management

- `encrypt_spec.tar.gz` - Encrypted specification archive
- `kmc_store_A` / `kmc_store_B` - KMC 3.0.0 key management stores (2592 bytes)
- Located at `/etc/wap/kmc_store_A` and `/mnt/jffs2/kmc_store_A`

- `etc/wap/spec/encrypt_spec` (0 bytes)
- `etc/wap/spec/encrypt_spec/encrypt_spec.tar.gz` (3784 bytes)
- `etc/wap/kmc_store_B` (2592 bytes)
  - KMC key management store
- `etc/wap/kmc_store_A` (2592 bytes)
  - KMC key management store
- `etc/wap/kmc_store_B` (2336 bytes)
  - KMC key management store
- `etc/wap/kmc_store_A` (2336 bytes)
  - KMC key management store

---

## Firmware Decompilation Summary

### Successfully Decompiled Firmware:

| Firmware | Kernel | Filesystem | Architecture |
|----------|--------|------------|-------------|
| HG8145V5-.bin (50MB) | Linux 4.4.219 | Squashfs 4.0 | ARM LE |
| HGONTV500.bin (48MB) | Linux 4.4.197 | Squashfs 4.0 | ARM LE |
| HG8247H UPGRADE.bin (27MB) | Linux 3.10.53-HULK2 | Squashfs 4.0 | ARM LE |
| HG8246M TO V5.bin (30MB) | Linux 3.10.53-HULK2 | Squashfs 4.0 | ARM LE |
| ATW-662G rootfs (12MB) | N/A | Squashfs 4.0 xz | ARM LE |
| General rootfs (10MB) | N/A | Squashfs 4.0 xz | ARM LE |
| NuCom-NC8700AC rootfs (8MB) | N/A | Squashfs 4.0 xz | ARM LE |

### Extraction Method:

1. HWNP firmware → binwalk extraction → uImage (kernel) + Squashfs (rootfs)
2. Squashfs → unsquashfs → full filesystem with keys, certs, binaries
3. Binaries → Capstone ARM disassembly → embedded key extraction
4. ZTE firmware (0x99999999 magic) → encrypted, requires ZTE-specific tooling
