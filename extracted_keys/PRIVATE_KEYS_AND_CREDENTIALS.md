========================================================================
  HUAWEI ONT FIRMWARE - KEYS & CERTIFICATES INVENTORY
========================================================================

------------------------------------------------------------------------
  CERTIFICATES
------------------------------------------------------------------------

  Path : etc/wap/root.crt
  Info : Huawei Equipment CA -> Fixed Network Product CA (2016-2041), SHA256WithRSA, 4096-bit issuer, 2048-bit subject

  Path : etc/wap/pub.crt
  Info : ont.huawei.com certificate (2020-2030), SHA256WithRSA, 2048-bit, issued by Fixed Network Product CA

  Path : etc/wap/plugroot.crt
  Info : HuaWei ONT CA self-signed root (2016-2026), SHA256WithRSA, 2048-bit, email=support@huawei.com

  Path : etc/wap/plugpub.crt
  Info : Plugin signing cert for ont.huawei.com (2017-2067), SHA256WithRSA, 2048-bit, issued by HuaWei ONT CA

  Path : etc/app_cert.crt
  Info : Huawei Root CA DER format (2015-2050), binary DER encoded

  Path : etc/hilinkcert/root.pem
  Info : root.home self-signed certificate (2014-2024, EXPIRED)

------------------------------------------------------------------------
  PRIVATE / PUBLIC KEYS
------------------------------------------------------------------------

  Path : configs/prvt.key
  Description     : RSA private key
  Encryption      : AES-256-CBC
  Dek Info        : AES-256-CBC,7EC546FB34CA7CD5599763D8D9AE6AC9
  Notes           : Needs Huawei hardware passphrase to decrypt

  Path : configs/plugprvt.key
  Description     : RSA private key for plugin signing
  Encryption      : AES-256-CBC
  Dek Info        : AES-256-CBC,8699C0FB1C5FA5FF6A3082AFD6082004
  Notes           : Needs Huawei hardware passphrase to decrypt

  Path : configs/su_pub_key
  Description     : RSA-256 bit PUBLIC key (trivially factorable)
  Encryption      : none
  Modulus Hex     : 0xcdb6cdaa1f20dad5
  Exponent        : 65537
  Notes           : Only 256 bits - CRITICALLY WEAK. Can be factored by any modern computer in seconds.

  Path : configs/dropbear_rsa_host_key
  Description     : Dropbear SSH host key
  Encryption      : none (binary format)
  Notes           : Binary dropbear key format, shared across devices

------------------------------------------------------------------------
  ENCRYPTION KEYS (embedded in binaries)
------------------------------------------------------------------------

  Name : aes_config_key
  Value           : Df7!ui%s9(lmV1L8
  Length Bytes    : 16
  Algorithm       : AES-128
  Purpose         : Config file encryption/decryption
  Binary Hits     : 5-18 binaries per firmware image
  Scope           : IDENTICAL across ALL Huawei ONT firmware versions (V300-V500)
  Binaries        : aescrypt2, hw_s_cltcfg, hw_ssp, cfgtool

  Name : su_pub_key_modulus
  Value           : 0xcdb6cdaa...1f20dad5
  Algorithm       : RSA-256
  Purpose         : Firmware signature verification
  Notes           : Trivially factorable by any modern computer

------------------------------------------------------------------------
  ENCRYPTED FILES
------------------------------------------------------------------------

  Path : configs/encrypt_spec_key.tar.gz
  Info : Encrypted tar.gz, likely AES encrypted with hardware-derived key

  Path : configs/prvt.key
  Info : AES-256-CBC encrypted RSA private key

  Path : configs/plugprvt.key
  Info : AES-256-CBC encrypted RSA private key (HG8145C uses DES-EDE3-CBC instead - weaker)

  Path : configs/dropbear_rsa_host_key
  Info : Binary dropbear key format

  Path : etc/wap/kmc_store_A
  Info : KMC (Key Management Center) keystore, 2592 bytes, only present in 5611 firmware

========================================================================
  NOTE: No raw PEM private key material is included.
  Refer to the firmware paths above to locate the actual
  key files within extracted firmware images.
========================================================================