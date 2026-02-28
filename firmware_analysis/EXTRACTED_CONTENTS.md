# Firmware Content Extraction Report

Extracted from: `realfirmware-net` repository (branch: `copilot/extract-and-organize-compressed-files`)

## Firmwares with SquashFS Extracted Successfully

| Firmware | SquashFS Offset | Files Found |
|----------|----------------|-------------|
| HG8145V5 General | 0x0028adee | rootfs completo |
| HG8145V5 Safaricom | 0x00232825 | rootfs completo |
| HG8145V5 Totalplay | 0x0023287c | rootfs completo |
| HG8245Q General | 0x00208b9a | rootfs completo |
| HG8246M General | 0x001b6ad4 | rootfs completo |
| HG8247H Vodafone | 0x00209e6c | rootfs completo |
| HGONTV500 Claro-Dom | 0x00295f7d | rootfs completo |
| ATW-662G rootfs | 0x00000000 | rootfs completo |
| General rootfs | 0x00000000 | rootfs completo |
| NuCom-NC8700AC rootfs | 0x00000000 | rootfs completo |
| Ping-7962V1 Telmex | 0x00002000 | rootfs completo |
| GX-Earth-2022 | 0x00002000 | rootfs completo |
| GX-Earth-4222 | 0x00002000 | rootfs completo |

## PEM Certificates Found

### Huawei HiLink Certificates (root.pem)
- **Subject**: CN=root.home, ST=Hubei, L=Wuhan, C=CN
- **Issuer**: CN=root.home (self-signed)
- **Valid**: 2014-07-14 to 2024-07-11
- **Email**: mobile@huawei.com
- **Found in**: HG8145V5, HG8245Q, HG8246M, HG8247H, HGONTV500

### Huawei HiLink Server Certificate (servercert.pem)
- **Subject**: CN=mediarouter.home, ST=Hubei, L=Wuhan, C=CN
- **Issuer**: CN=root.home
- **Valid**: 2014-07-14 to 2024-07-11
- **Found in**: All Huawei firmwares

### Realtek SSL Certificate (ssl_cert.pem)
- **Subject**: CN=192.168.1.1, O=realtek, ST=Jiangsu, C=CN
- **Issuer**: Self-signed
- **Valid**: 2010-11-08 to 2035-06-30
- **Found in**: ATW-662G, General, GX-Earth-2022, GX-Earth-4222, NuCom-NC8700AC, Ping-7962V1

### Realtek Client Certificate (client.pem)
- **Subject**: CN=00E04C-00000001, O=Realtek, ST=Taiwan
- **Issuer**: CN=172.21.70.41 (Realtek internal)
- **Valid**: 2008-06-03 to 2010-06-03 (EXPIRED)
- **Found in**: ATW-662G, General, GX-Earth-2022, GX-Earth-4222, Ping-7962V1

### Totalplay Root CA (root_1_totalplay.pem)
- **Subject**: CN=Huawei, O=TotalPlay, C=Me (Mexico)
- **Algorithm**: SHA256withRSA
- **Valid**: 2020-07-28 to 2030-07-26
- **Found in**: HGONTV500

### Telmex Root CA (root_1_telmex.pem)
- **Subject**: CN=Example CA, O=Root CA of Handy
- **Email**: zhangxiaotian@huawei.com
- **Algorithm**: MD4withRSA (WEAK!)
- **Valid**: 2019-07-12 to 2019-08-11 (EXPIRED)
- **Found in**: HGONTV500

## Private Keys Found

### prvt.key (Huawei ONT Private Key)
- **Type**: RSA Private Key
- **Encryption**: AES-256-CBC
- **DEK-Info**: 7EC546FB34CA7CD5599763D8D9AE6AC9
- **Status**: ENCRYPTED (needs Huawei passphrase)
- **Found in**: ALL Huawei firmwares (HG8145V5, HG8245Q, HG8246M, HG8247H, HGONTV500)

### plugprvt.key (Plugin Private Key)
- **Type**: RSA Private Key
- **Encryption**: AES-256-CBC
- **DEK-Info**: 8699C0FB1C5FA5FF6A3082AFD6082004
- **Status**: ENCRYPTED
- **Found in**: ALL Huawei firmwares

### prvt_1_telmex.pem (Telmex ISP Private Key)
- **Type**: RSA Private Key
- **Encryption**: AES-256-CBC
- **DEK-Info**: E9C345C99596E49DC46E73AC1F81F08D
- **Status**: ENCRYPTED
- **Found in**: HGONTV500 Claro-Dominicana

### prvt_1_totalplay.pem (Totalplay ISP Private Key)
- **Type**: RSA Private Key
- **Encryption**: DES-EDE3-CBC (WEAKER than AES!)
- **DEK-Info**: 6CC48C2680987560
- **Status**: ENCRYPTED
- **Found in**: HGONTV500 Claro-Dominicana

### ssl_key.pem (Realtek SSL Private Key)
- **Type**: RSA Private Key
- **Encryption**: NONE (UNENCRYPTED!)
- **Status**: ✅ VALID, openssl reports "RSA key ok"
- **Found in**: ATW-662G, General, GX-Earth-2022, GX-Earth-4222, NuCom-NC8700AC, Ping-7962V1

### serverkey.pem (HiLink Server Key)
- **Type**: Binary/DER format
- **Status**: Non-standard encoding
- **Found in**: ALL Huawei firmwares

### su_pub_key (Superuser Public Key)
- **Type**: RSA Public Key (RSA-256 bit - TRIVIALLY FACTORABLE!)
- **Modulus**: MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM22zaKqNheaojn8HUjOnoIZTMV3pjGJei31Df0fINrVAgMBAAE=
- **Key size**: 256 bits (EXTREMELY WEAK - can be factored in seconds)
- **Found in**: ALL Huawei firmwares

### Dropbear RSA Host Keys
- **Type**: Dropbear SSH RSA host key (binary format)
- **Found in**: ALL firmwares with SSH support
- **Format**: `\x00\x00\x00\x07ssh-rsa` header

## Credentials Found

### /etc/shadow (Password Hashes)
All Huawei firmwares share IDENTICAL shadow files:
```
root:aqnaBbVaP.9Zo:14453:0:99999:7:::
osgi:$1$U6vz.JFk$robzQ3kXsVf/GNcal1VS/1:0:0:99999:7:::
nobody:!:11141:0:99999:7:::
sshd:*:11880:0:99999:7:-1:-1:0
```
- **root**: DES crypt hash `aqnaBbVaP.9Zo` (WEAK, crackable)
- **osgi**: MD5 crypt hash `$1$U6vz.JFk$robzQ3kXsVf/GNcal1VS/1`

### /etc/wap/passwd (System Users)
Firmware services running as separate users:
- `root` (UID 0) - superuser
- `osgi` (UID 1000) - Java OSGi framework
- `web` (UID 1001) - web interface
- `cli` (UID 1002) - CLI access
- `cfg_cwmp` (UID 3007) - TR-069 CWMP agent
- `cfg_omci` (UID 3009) - OMCI configuration
- `srv_ssmp` (UID 3008) - SSMP service
- `srv_samba` (UID 3002) - Samba file sharing
- `srv_snmp` (UID 3017) - SNMP agent
- `srv_wifi` (UID 3015) - WiFi service
- `srv_kmc` (UID 3020) - Key Management Center

### Known AES Encryption Key
- **Key**: `Df7!ui%s9(lmV1L8`
- **Algorithm**: AES-256-CBC
- **Usage**: Configuration encryption across ALL Huawei ONT firmwares
- **Cross-firmware**: Identical in HG8145V5, HG8245, HG8246M, HG8247H, HGONTV500

## DER Certificates Found

Multiple DER-encoded X.509 certificates found embedded in Huawei HWNP firmware headers:
- **plugroot.crt** - HuaWei ONT CA (plugin signing root)
- **plugpub.crt** - Plugin public certificate
- **root.crt** - Huawei Equipment CA → Fixed Network Product CA
- **pub.crt** - ont.huawei.com certificate

## Encrypted Files Analysis

### Huawei HWNP Firmware Packages
All Huawei .bin files use HWNP header format with embedded:
- UpgradeCheck.xml (upgrade validation)
- signature (firmware signature)
- dealosgfile.sh (OSGi deployment script)
- kernel, uboot, rootfs sections

### Encrypted Private Keys
The following keys are encrypted and require the Huawei hardware passphrase:
- `prvt.key` - AES-256-CBC encrypted
- `plugprvt.key` - AES-256-CBC encrypted
- `prvt_1_telmex.pem` - AES-256-CBC encrypted
- `prvt_1_totalplay.pem` - DES-EDE3-CBC encrypted

## Firmware Types Summary

| Type | Devices | Format |
|------|---------|--------|
| Huawei HWNP | HG8145V5, HG8245, HG8246M, HG8247H, HGONTV500 | HWNP header + SquashFS rootfs |
| ZTE | F660, F660E, F670L, F680 | Gzip compressed + SquashFS |
| Realtek/OEM | ATW-662G, NuCom-NC8700AC, GX-Earth, Ping-7962V1 | SquashFS rootfs + uImage |
