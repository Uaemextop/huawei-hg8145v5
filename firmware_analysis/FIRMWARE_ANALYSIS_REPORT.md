# Firmware Analysis Report

Generated: 2026-02-28T19:03:02.007917+00:00

Source: realfirmware-net repository (branch: copilot/extract-and-organize-compressed-files)

## Summary

| Category | Count |
|----------|-------|
| Firmware files analyzed | 46 |
| PEM Certificates | 0 |
| PEM Keys | 0 |
| DER Certificates | 118 |
| Credentials | 225 |
| Binary Key Material | 116 |
| Encrypted Files | 41 |
| Capstone Findings | 255 |

## Firmware Inventory

| File | Size | Type | MD5 |
|------|------|------|-----|
| ATW-662G__General__fwu_ver | 46.0 B | Unknown format (magic: 56302e30) | `aafe44f6aad2...` |
| ATW-662G__General__rootfs | 11.8 MB | Header: SquashFS (little-endian); Embedded Gzip compressed a | `3a9dc40aac29...` |
| ATW-662G__General__uImage | 3.7 MB | Header: U-Boot uImage; Embedded Gzip compressed at offset 0x | `43397fa81e02...` |
| GX-Earth-2022__General__earth-2022-E2022-2.1.1-R.img | 12.6 MB | Embedded SquashFS (little-endian) at offset 0x2000; Embedded | `5551f7fd8b89...` |
| GX-Earth-4222__General__earth-4222-E4222-2.0.7-R.img | 13.7 MB | Embedded SquashFS (little-endian) at offset 0x2000; Embedded | `13b3ddbcedfa...` |
| General__General__fwu_ver | 60.0 B | Unknown format (magic: 56302e30) | `fb2a2b3e5122...` |
| General__General__hw_ver | 5.0 B | Unknown format (magic: 736b6970) | `899b03fc2f59...` |
| General__General__rootfs | 10.1 MB | Header: SquashFS (little-endian); Embedded Gzip compressed a | `07a0ada8540e...` |
| General__General__uImage | 3.3 MB | Header: U-Boot uImage; Embedded Gzip compressed at offset 0x | `ab802465c71c...` |
| Huawei-HG8145Q2__General__HG8145Q2 | 2.3 KB | Embedded PE executable at offset 0x20a | `c783c52beeb2...` |
| Huawei-HG8145V5V3__Telmex__V2.bin | 1.7 MB | Header: Huawei HWNP firmware; Embedded Gzip compressed at of | `a2f3e2400bd4...` |
| Huawei-HG8145V5__Conversion-EPON__HG8145V5-R019-EPON.bin | 15.3 KB | Header: Huawei HWNP firmware | `933c5038f004...` |
| Huawei-HG8145V5__Conversion-XPON__HG8145V5-XPON.bin | 21.5 KB | Header: Huawei HWNP firmware | `015b1930f692...` |
| Huawei-HG8145V5__General__HG8145V5-.bin | 47.9 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `ed450e26d03d...` |
| Huawei-HG8145V5__Safaricom__STEP_1_HG8145V.bin | 36.8 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `2c02d260d332...` |
| Huawei-HG8145V5__Totalplay__Total_G150.bin | 36.9 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `8358a0c3c368...` |
| Huawei-HG8145X6-10__Totalplay__TOTAL.bin | 45.8 MB | Header: Huawei HWNP firmware; Embedded Gzip compressed at of | `2cefffdcec29...` |
| Huawei-HG8245A__Conversion-XPON__HG8245A_XPON.bin | 4.9 KB | Header: Huawei HWNP firmware | `d72b17a677e6...` |
| Huawei-HG8245H5__Conversion-EPON__HG8245H5_EPON.bin | 245.0 KB | Header: Huawei HWNP firmware; Embedded Gzip compressed at of | `6ac4faff270a...` |
| Huawei-HG8245H__Conversion-EPON__HG8245H_EPON.bin | 4.9 KB | Header: Huawei HWNP firmware | `79352f650745...` |
| Huawei-HG8245H__Conversion-XPON__HG8245H_XPON.bin | 684.2 KB | Header: Huawei HWNP firmware; Embedded Gzip compressed at of | `bd8f3e9bfadf...` |
| Huawei-HG8245H__General__HG8245H-COMMON-OK.bin | 3.4 KB | Header: Huawei HWNP firmware | `418a737fee52...` |
| Huawei-HG8245Q__General__HG8245Q_SUBIR_UPGRADE.bin | 27.2 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `d5fbb48fe78d...` |
| Huawei-HG8245W5-6T__Claro-Argentina__HG__G40.bin | 195.3 KB | Header: Huawei HWNP firmware | `389d06278786...` |
| Huawei-HG8245W5-6T__Claro-Argentina__unlock.bin | 202.3 KB | Header: Huawei HWNP firmware | `1a70fc4f2608...` |
| Huawei-HG8245W5-6T__General__HG8245W5_T6-COMMON-OK.bin | 20.5 KB | Header: Huawei HWNP firmware | `c0ff66ca7dd5...` |
| Huawei-HG8245W5-6T__General__shell.bin | 1.8 MB | Header: Huawei HWNP firmware; Embedded Gzip compressed at of | `4b2356b18b90...` |
| Huawei-HG8245W5-6T__General__unlock_1.bin | 4.0 KB | Header: Huawei HWNP firmware | `0a5652f524e0...` |
| Huawei-HG8245W5-6T__Personal-Paraguay__R020.bin | 17.3 KB | Header: Huawei HWNP firmware | `7d7ed5dec311...` |
| Huawei-HG8245__General__HG8245_common_ok.bin | 27.2 KB | Header: Huawei HWNP firmware | `a0d96a7e4d25...` |
| Huawei-HG8246M__Conversion-XPON__HG8546M_XPON.bin | 233.1 KB | Header: Huawei HWNP firmware; Embedded Gzip compressed at of | `9626fc4aa75c...` |
| Huawei-HG8246M__General__Firmware_HG8246M_TO_V5.bin | 28.9 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `6fbc4b9fad55...` |
| Huawei-HG8247H__Vodafone__HG8247H_UPGRADE.bin | 26.2 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `1d4932815cdc...` |
| Huawei-HGONTV500__Claro-Dominicana__HGONTV500.bin | 46.4 MB | Header: Huawei HWNP firmware; Embedded U-Boot uImage at offs | `843ca84940b4...` |
| NuCom-NC8700AC__General__fwu_ver | 60.0 B | Unknown format (magic: 56302e30) | `ad77e8c31cf3...` |
| NuCom-NC8700AC__General__rootfs | 7.6 MB | Header: SquashFS (little-endian); Embedded Gzip compressed a | `4b9115a2546f...` |
| NuCom-NC8700AC__General__uImage | 3.2 MB | Header: U-Boot uImage; Embedded Gzip compressed at offset 0x | `aaf2cbc68d82...` |
| Ping-7962V1__Telmex__FOlt.bin | 13.7 MB | Embedded SquashFS (little-endian) at offset 0x2000; Embedded | `61a0ef7566e2...` |
| ZTE-F660E__ETB-Colombia__ZTE_F660E.bin | 20.0 MB | Embedded Gzip compressed at offset 0xa8724; Embedded PE exec | `e278ce10b337...` |
| ZTE-F660__General__F660_H248_V2.30.62P2T1_UPGRADE_BOOTLDR.bin | 10.5 MB | Embedded Gzip compressed at offset 0xd8ba; Embedded PE execu | `02724a6b175c...` |
| ZTE-F670L__Airtel-India__F670L_V9..bin | 23.0 MB | Embedded Gzip compressed at offset 0x246af; Embedded PE exec | `bd178fc2d146...` |
| ZTE-F670L__General__F670L_V1.1.20P1N55.bin | 19.0 MB | Embedded Gzip compressed at offset 0x3932f; Embedded PE exec | `685af4b8b4c4...` |
| ZTE-F670L__General__F670L_V1.1.20P3N4D_UPGRADE_BOOTLDR.bin | 19.2 MB | Embedded Gzip compressed at offset 0x2cec5; Embedded PE exec | `8169a3826f94...` |
| ZTE-F670L__Telmex__respaldo.bin | 25.9 KB | Unknown format (magic: 04030201) | `d1087d0cacea...` |
| ZTE-F670L__Telmex__upgrade.bin | 23.6 MB | Embedded Gzip compressed at offset 0x26113; Embedded PE exec | `6d2b89b300c7...` |
| ZTE-F680__CNT-Ecuador__F680_V6.0..bin | 20.3 MB | Embedded Gzip compressed at offset 0x204ad; Embedded PE exec | `160508c03821...` |

## Encrypted File Analysis

### ATW-662G__General__rootfs
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### ATW-662G__General__uImage
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### GX-Earth-2022__General__earth-2022-E2022-2.1.1-R.img
- High-entropy data: 99.2%
- **high_entropy**: 99.2% of first 1MB has high entropy (encrypted/compressed)

### GX-Earth-4222__General__earth-4222-E4222-2.0.7-R.img
- High-entropy data: 99.2%
- **high_entropy**: 99.2% of first 1MB has high entropy (encrypted/compressed)

### General__General__rootfs
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### General__General__uImage
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8145V5V3__Telmex__V2.bin
- High-entropy data: 91.6%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 882383616
  - version: `
- **high_entropy**: 91.6% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8145V5__Conversion-EPON__HG8145V5-R019-EPON.bin
- High-entropy data: 26.7%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 3980132352
  - version: ;

### Huawei-HG8145V5__Conversion-XPON__HG8145V5-XPON.bin
- High-entropy data: 33.3%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 3394568192
  - version: h

### Huawei-HG8145V5__General__HG8145V5-.bin
- High-entropy data: 50.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 3514891778
  - version: mJ

### Huawei-HG8145V5__Safaricom__STEP_1_HG8145V.bin
- High-entropy data: 58.2%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 2353614082
  - version: bSF
- **high_entropy**: 58.2% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8145V5__Totalplay__Total_G150.bin
- High-entropy data: 58.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 907955970
  - version: H
- **high_entropy**: 58.0% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8145X6-10__Totalplay__TOTAL.bin
- High-entropy data: 99.9%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 4232829954
  - version: hzs%
- **high_entropy**: 99.9% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8245A__Conversion-XPON__HG8245A_XPON.bin
- High-entropy data: 0.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 538116096
  - version: h

### Huawei-HG8245H5__Conversion-EPON__HG8245H5_EPON.bin
- High-entropy data: 41.4%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 2916287232
  - version:  

### Huawei-HG8245H__Conversion-EPON__HG8245H_EPON.bin
- High-entropy data: 0.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 538116096
  - version: zj

### Huawei-HG8245H__Conversion-XPON__HG8245H_XPON.bin
- High-entropy data: 99.4%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 1940916736
  - version: h
- **high_entropy**: 99.4% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8245H__General__HG8245H-COMMON-OK.bin
- High-entropy data: 0.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 1628241920
  - version: #

### Huawei-HG8245Q__General__HG8245Q_SUBIR_UPGRADE.bin
- High-entropy data: 65.5%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 2848436993
  - version: !
- **high_entropy**: 65.5% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8245W5-6T__Claro-Argentina__HG__G40.bin
- High-entropy data: 2.6%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 252510976
  - version: ,

### Huawei-HG8245W5-6T__Claro-Argentina__unlock.bin
- High-entropy data: 2.5%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 4196926208
  - version: h

### Huawei-HG8245W5-6T__General__HG8245W5_T6-COMMON-OK.bin
- High-entropy data: 35.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 3595632640
  - version: {

### Huawei-HG8245W5-6T__General__shell.bin
- High-entropy data: 91.8%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 3358137344
  - version: h
- **high_entropy**: 91.8% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8245W5-6T__General__unlock_1.bin
- High-entropy data: 0.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 2819555328
  - version: h

### Huawei-HG8245W5-6T__Personal-Paraguay__R020.bin
- High-entropy data: 41.2%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 3041132544
  - version: h

### Huawei-HG8245__General__HG8245_common_ok.bin
- High-entropy data: 0.0%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 2020343808
  - version: 7

### Huawei-HG8246M__Conversion-XPON__HG8546M_XPON.bin
- High-entropy data: 41.2%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 4188209920
  - version: Q

### Huawei-HG8246M__General__Firmware_HG8246M_TO_V5.bin
- High-entropy data: 97.9%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 2297089537
  - version: o
- **high_entropy**: 97.9% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HG8247H__Vodafone__HG8247H_UPGRADE.bin
- High-entropy data: 65.4%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 683385345
  - version: b]
- **high_entropy**: 65.4% of first 1MB has high entropy (encrypted/compressed)

### Huawei-HGONTV500__Claro-Dominicana__HGONTV500.bin
- High-entropy data: 55.7%
- **HWNP**: Huawei HWNP firmware package
  - magic: HWNP
  - header_size: 784459010
  - version: K
- **high_entropy**: 55.7% of first 1MB has high entropy (encrypted/compressed)

### NuCom-NC8700AC__General__rootfs
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### NuCom-NC8700AC__General__uImage
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### Ping-7962V1__Telmex__FOlt.bin
- High-entropy data: 99.2%
- **high_entropy**: 99.2% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F660E__ETB-Colombia__ZTE_F660E.bin
- High-entropy data: 57.7%
- **high_entropy**: 57.7% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F660__General__F660_H248_V2.30.62P2T1_UPGRADE_BOOTLDR.bin
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F670L__Airtel-India__F670L_V9..bin
- High-entropy data: 87.4%
- **high_entropy**: 87.4% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F670L__General__F670L_V1.1.20P1N55.bin
- High-entropy data: 87.5%
- **high_entropy**: 87.5% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F670L__General__F670L_V1.1.20P3N4D_UPGRADE_BOOTLDR.bin
- High-entropy data: 87.5%
- **high_entropy**: 87.5% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F670L__Telmex__respaldo.bin
- High-entropy data: 100.0%
- **high_entropy**: 100.0% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F670L__Telmex__upgrade.bin
- High-entropy data: 87.4%
- **high_entropy**: 87.4% of first 1MB has high entropy (encrypted/compressed)

### ZTE-F680__CNT-Ecuador__F680_V6.0..bin
- High-entropy data: 87.5%
- **high_entropy**: 87.5% of first 1MB has high entropy (encrypted/compressed)

## Known Encryption Keys

### AES Key (Common across Huawei ONT firmware)
- **Key**: `Df7!ui%s9(lmV1L8`
- **Algorithm**: AES-256-CBC
- **Usage**: Firmware configuration encryption
- **Found in**: Multiple Huawei firmware binaries
