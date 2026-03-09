# Capstone Disassembly Analysis

Binary analysis of crypto-related firmware executables and libraries.


## aescrypt2 (17,692 bytes)
**MD5**: `b5027f942e6cbe8ce9cb00a2b963162f`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x125c

### Crypto-Related Strings (25)
| Offset | String |
|--------|--------|
| 0x85f | `HW_SSL_Sha2HmacStart` |
| 0x87e | `HW_SSL_Sha2HmacFinish` |
| 0x894 | `HW_SSL_Sha2Update` |
| 0x8b3 | `HW_KMC_CfgGetKey` |
| 0x970 | `HW_SSL_AesSetKeyEnc` |
| 0x984 | `HW_SSL_Sha2Finish` |
| 0xa00 | `HW_OS_AESCBCDecrypt` |
| 0xa14 | `HW_SSL_Sha2Start` |
| 0xa25 | `HW_SSL_AesCryptEcb` |
| 0xa4a | `HW_SSL_AesSetKeyDec` |
| 0xa5e | `HW_OS_AESCBCEncrypt` |
| 0xa72 | `HW_SSL_Sha2HmacUpdate` |
| 0xb60 | `HW_CTOOL_GetKeyChipStr` |
| 0x307b | `Df7!ui%s9(lmV1L8` |
| 0x30db | `<%s:%d>get key failed` |
| 0x3259 | `<%s:%d>file read key len failed, errno (%d)` |
| 0x3287 | `<%s:%d>file read key len err, len (%d), maxlen (%d)` |
| 0x32bd | `<%s:%d>file (%s) read head key failed, errno (%d)` |
| 0x3405 | `<%s:%d>MODE_DECRYPT::fread(16 bytes) failed` |
| 0x3454 | `<%s:%d>MODE_DECRYPT::fread(bytes) failed` |
| 0x3480 | `<%s:%d>HMAC check failed: wrong key, or file corrupted.` |
| 0x34c9 | `  aescrypt2 <mode> <input filename> <output filename>` |
| 0x3500 | `  <mode>: 0 = encrypt, 1 = decrypt` |
| 0x3524 | `  example: aescrypt2 0 file file.aes` |
| 0x4046 | `.gnu.hash` |

### Key Code Sections (Capstone ARM Disassembly)

#### Known AES Key Reference @ 0x307b
```asm
  0x0000303b: stclt    p5, c13, [fp], {0x84}
  0x0000303f: ldcvc    p2, c6, [r6, #0x268]
```

#### AES Algorithm @ 0xa06
```asm
  0x000009c6: rsbeq    r6, fp, r5, ror #10
  0x000009ca: svcmi    #0x5f5748
  0x000009ce: subvc    r5, pc, r3, asr pc
  0x000009d2: stmdami  r0, {r0, r2, r5, r6, sb, sl, fp, sp, lr}
  0x000009d6: movtpl   r5, #0xff57
  0x000009da: strbtvc  r4, [r5], #-0x75f
  0x000009de: ldrbtvc  r6, [r3], #-0x14c
  0x000009e2: rsbseq   r7, r2, r5, asr #4
  0x000009e6: svcmi    #0x5f5748
  0x000009ea: mcrrvs   p15, #5, r5, r3, c3
  0x000009ee: rsbeq    r7, r5, pc, ror #6
  0x000009f2: svcmi    #0x5f5748
  0x000009f6: ldrbvc   r5, [r3], #-0xf53
  0x000009fa: stclvs   p14, c4, [r3, #-0x1c8]
  0x000009fe: smlsldxpl r0, r8, r0, r0
```

#### Decrypt Function @ 0x351b
```asm
  0x000034db: cdpvs    p12, #6, c3, c9, c0, #1
  0x000034df: rsbshs   r7, r4, r0, ror r5
  0x000034e3: strbvs   r6, [ip, #-0x966]!
  0x000034e7: strbvs   r6, [sp, #-0x16e]!
  0x000034eb: svcvs    #0x3c203e
  0x000034ef: ldrbvc   r7, [r0, #-0x475]!
  0x000034f3: stmdbvs  r6!, {r2, r4, r5, r6, sp} ^
```

#### Encrypt Function @ 0x350e
```asm
  0x000034ce: rsbsvc   r7, sb, r3, ror #4
  0x000034d2: stclo    p2, c3, [r0], #-0x1d0
  0x000034d6: strbvs   r6, [r4, #-0xf6d]!
  0x000034da: ldmdbvs  ip!, {r1, r2, r3, r4, r5, sp}
  0x000034de: ldrbtvc  r7, [r5], #-0x6e
  0x000034e2: stclvs   p6, c6, [sb], #-0x80
  0x000034e6: stclvs   p14, c6, [r1, #-0x194]!
  0x000034ea: stclo    p14, c3, [r0], #-0x194
  0x000034ee: rsbsvc   r7, r4, pc, ror #10
  0x000034f2: qsub16vs r7, r0, r5
  0x000034f6: cdpvs    p12, #6, c6, c5, c9, #3
  0x000034fa: cdplo    p13, #6, c6, c5, c1, #3
  0x000034fe: eorhs    r0, r0, sl, lsl #20
  0x00003502: strbtvs  r6, [pc], #-0xd3c
  0x00003506: eorshs   r3, sl, r5, ror #28
```


## decrypt_boardinfo (5,404 bytes)
**MD5**: `fbe8cd4f073ea9c2dc6aaf4f5635e875`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x8f8

### Crypto-Related Strings (2)
| Offset | String |
|--------|--------|
| 0x55b | `DM_DecryptBoardInfo` |
| 0x1046 | `.gnu.hash` |

### Key Code Sections (Capstone ARM Disassembly)


## kmc_tool (9,500 bytes)
**MD5**: `8ae6e1a3bc7e4f6a19d3a3819714a061`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0xde0

### Crypto-Related Strings (18)
| Offset | String |
|--------|--------|
| 0x761 | `KMC_IsNowHardWareCrypt` |
| 0x7b6 | `KmcGetMkDetail` |
| 0x7ef | `KMC_CheckHashEnd` |
| 0x81b | `KMC_MKExsit` |
| 0x8c2 | `KMCTOOL_CopyFile` |
| 0x8f4 | `KMCTOOL_Init_ModuleKmc` |
| 0x924 | `KMCTOOL_NeedRestore` |
| 0x938 | `KMCTOOL_WriteKMCToFile` |
| 0x958 | `KMCTOOL_PriGetKey` |
| 0x1344 | `kmc_tool_main.c` |
| 0x1357 | `/var/kmc_tmp_info` |
| 0x1369 | `/mnt/jffs2/kmc_store_A` |
| 0x1380 | `/etc/wap/kmc_store_A` |
| 0x1395 | `/mnt/jffs2/kmc_store_B` |
| 0x13ac | `/etc/wap/kmc_store_B` |
| 0x13c1 | `Copy kmcstore file to jffs2!` |
| 0x13e4 | `KMC version[%s], is hardware crypt[%d]` |
| 0x2046 | `.gnu.hash` |

### Key Code Sections (Capstone ARM Disassembly)

#### KMC Key Store @ 0x1374
```asm
  0x00001334: andeq    r0, r0, r5, lsl #1
  0x00001338: push     {r0, lr}
  0x0000133c: pop      {r0, lr}
  0x00001340: bx       lr
  0x00001344: svcpl    #0x636d6b
  0x00001348: stclvs   p15, c6, [pc], #-0x1d0
  0x0000134c: stmdbvs  r1!, {r0, r1, r2, r3, r4, r6, r8, sl, fp, sp, lr} ^
  0x00001350: rsbeq    r2, r3, lr, ror #28
  0x00001354: svchs    #0x2b77
  0x00001358: svchs    #0x726176
  0x0000135c: svcpl    #0x636d6b
  0x00001360: svcpl    #0x706d74
  0x00001364: svcvs    #0x666e69
  0x00001368: cdpvs    p15, #6, c2, c13, c0, #0
  0x0000136c: uqsub16vs r2, sl, r4
```


## kmc (34,180 bytes)
**MD5**: `a5f225019ee245e1168731a0352da346`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x25f0

### Crypto-Related Strings (84)
| Offset | String |
|--------|--------|
| 0x1224 | `__aeabi_uidivmod` |
| 0x13a5 | `HW_Init_KMC` |
| 0x13b1 | `KmcGetMk` |
| 0x13ba | `KmcSetMkStatus` |
| 0x13f7 | `KmcActivateMk` |
| 0x1474 | `KmcRmvMk` |
| 0x1494 | `HW_OS_AESDecrypt_Ex` |
| 0x14bf | `KmcUpdateRootKey` |
| 0x14e1 | `KmcSetRootKeyCfg` |
| 0x150c | `KmcGetMkCount` |
| 0x1554 | `HW_AES_BinToPlainEx` |
| 0x15c0 | `HW_KMC_CfgSetKey` |
| 0x15da | `KMC_MKExsit` |
| 0x1611 | `KMC_UpdateKMCFileFromEtcDir` |
| 0x162d | `KmcGetRootKeyCfg` |
| 0x16cb | `KmcGetRootKeyInfo` |
| 0x1740 | `KMC_RegisterMkExWithCreateDomain` |
| 0x1761 | `KmcGetMkStatus` |
| 0x17d4 | `HW_KMC_Domain_MK_AddRPC` |
| 0x17ec | `HW_KMC_Del_CheckDomainID` |
| 0x1805 | `HW_KMC_SmoothCreateUnVisibleKey` |
| 0x1825 | `HW_KMC_CheckActive` |
| 0x1846 | `KMC_CheckDomainPara` |
| 0x185a | `HW_Init_ModuleKmc` |
| 0x186c | `HW_KMC_SmoothRK` |
| 0x187c | `HW_KMC_AddDomain` |
| 0x188d | `HW_KMC_DelAllMKInstByDomain` |
| 0x18b0 | `KMC_ModifyMKTimer` |
| 0x18c2 | `HW_KMC_CheckCfgKey` |
| 0x18e1 | `HW_KMC_RK_SetRPC` |
| 0x18f2 | `HW_KMC_RPC_GetDomainInstance` |
| 0x190f | `HW_KMC_GetDomainID` |
| 0x1922 | `HW_KMC_Domain_MK_SetRPC` |
| 0x193a | `KMCMsgProc` |
| 0x1945 | `HW_KMC_Domain_SetRPC` |
| 0x195a | `HW_KMC_PM_MsgProc` |
| 0x196c | `HW_KMC_RegisterPM` |
| 0x197e | `HW_KMC_CheckCfgNewNodeExist` |
| 0x199a | `HW_KMC_GenKeyId` |
| 0x19aa | `HW_KMC_DelTheFirstMkByDomain` |
| 0x19c7 | `HW_KMC_NewCfg` |
| 0x19d5 | `HW_KMC_ResetCfgKey` |
| 0x19e8 | `HW_KMC_SmoothCfgNewNode` |
| 0x1a00 | `HW_KMC_Domain_GetRPC` |
| 0x1a15 | `HW_KMC_SmoothMK` |
| 0x1a36 | `HW_KMC_Domain_MK_SetPreCheck` |
| 0x1a53 | `KMC_AutoUpdateMK` |
| 0x1a64 | `HW_KMC_Add_CheckDomainID` |
| 0x1a7d | `HW_KMC_AddEmptyCfgNewNode` |
| 0x1a97 | `g_astKmcRpcCalls` |
| 0x1aa8 | `KMC_UpdateMK` |
| 0x1ab5 | `HW_KMC_GetKeyID` |
| 0x1ac5 | `HW_KMC_GenerateVisibleKey` |
| 0x1adf | `HW_KMC_GenKeyToKeyStore` |
| 0x1b04 | `HW_KMC_GetDomainMkNumber` |
| 0x1b29 | `KMC_InitMKTimer` |
| 0x1b39 | `HW_KMC_DelKeyFromCtree` |
| 0x1b69 | `HW_KMC_Domain_MK_DelRPC` |
| 0x1b81 | `HW_KMC_Domain_MK_GetRPC` |
| 0x1b99 | `HW_KMC_RK_SetPreCheck` |

### Key Code Sections (Capstone ARM Disassembly)

#### Known AES Key Reference @ 0x67d0
```asm
  0x00006790: svcpl    #0x434d4b
  0x00006794: stmdbvs  r4!, {r0, r2, r3, r6, r8, sb, sl, fp, sp, lr} ^
  0x00006798: blmi     #0x1364d38
  0x0000679c: strbvs   r6, [sp, #-0x954]!
```

#### AES Algorithm @ 0x149a
```asm
  0x0000145a: stclvs   p5, c6, [r1], #-0x148
  0x0000145e: strbvs   r6, [sp, #-0x954]!
  0x00001462: smlsldxpl r0, r8, r2, r0
  0x00001466: svcpl    #0x534f5f
  0x0000146a: rsbspl   r6, r4, #0x11c00000
  0x0000146e: svcvs    #0x646e61
  0x00001472: stclvs   p0, c0, [fp, #-0x1b4]
  0x00001476: strbtvc  r5, [sp], -r3, ror #4
  0x0000147a: stmdami  r0, {r0, r2, r3, r6, r8, sb, fp, sp, lr}
  0x0000147e: submi    r5, r4, #0x15c
  0x00001482: svcpl    #0x495041
  0x00001486: svcmi    #0x746547
  0x0000148a: vmlsvs.f32 s13, s18, s5
  0x0000148e: strbvc   r7, [lr, #-0x473]
  0x00001492: strbpl   r0, [r8, -sp, rrx]
```


## dropbear (251,616 bytes)
**MD5**: `47d91fda3255c972284df6aeef9adcaf`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x2a84

### Crypto-Related Strings (283)
| Offset | String |
|--------|--------|
| 0xffb | `signal` |
| 0x3270b | `DROPBEAR_DEBUG_NET_TIMESTAMP` |
| 0x32728 | `Resetting Dropbear TRACE timestamps` |
| 0x3274c | `DROPBEAR_TRACE2` |
| 0x3277b | `leave getauthline: line too long` |
| 0x327b7 | `signal() error` |
| 0x32996 | `negative bignum` |
| 0x329c5 | `enter buf_get_dss_pub_key` |
| 0x329e5 | `leave buf_get_dss_pub_key: failed reading mpints` |
| 0x32a34 | `leave buf_get_dss_pub_key: success` |
| 0x32a57 | `enter dsa_key_free` |
| 0x32a6a | `enter dsa_key_free: key == NULL` |
| 0x32a8a | `leave dsa_key_free` |
| 0x32b16 | `enter buf_put_dss_sign` |
| 0x32b37 | `writelen <= SHA1_HASH_SIZE` |
| 0x32b52 | `leave buf_put_dss_sign` |
| 0x32b79 | `enter sign_key_md5_fingerprint. line:%d` |
| 0x32ba1 | `md5 ` |
| 0x32ba6 | `Bad key type %d` |
| 0x32bb6 | `signkey_type_from_name unexpected key type.` |
| 0x32be2 | `enter buf_get_pub_key` |
| 0x32bf8 | `buf_get_pub_key bad type - got %d, expected %d` |
| 0x32c27 | `buf_get_pub_key keytype is %d` |
| 0x32c45 | `leave buf_get_pub_key` |
| 0x32c5b | `enter buf_get_priv_key` |
| 0x32c72 | `wrong key type: %d %d` |
| 0x32c88 | `leave buf_get_priv_key` |
| 0x32c9f | `enter buf_put_pub_key` |
| 0x32cb5 | `Bad key types in buf_put_pub_key` |
| 0x32cd6 | `leave buf_put_pub_key` |
| 0x32cec | `enter buf_put_priv_key` |
| 0x32d03 | `leave buf_put_priv_key: dss done` |
| 0x32d24 | `leave buf_put_priv_key: rsa done` |
| 0x32d45 | `leave buf_put_priv_key: ecdsa done` |
| 0x32d68 | `Bad key types in put pub key` |
| 0x32d85 | `enter sign_key_free` |
| 0x32d99 | `leave sign_key_free` |
| 0x32dad | `enter sign_key_fingerprint_ex. keyblob:[%s] keybloblen:%d type:%d` |
| 0x32def | `enter sign_key_sha1_fingerprint. line:%d` |
| 0x32e18 | `sha1 ` |
| 0x32e1e | `Non-matching signing type` |
| 0x32e49 | `No DSS key to verify signature` |
| 0x32e68 | `No RSA key to verify signature` |
| 0x32e87 | `checkpubkey: base64 decode failed` |
| 0x32ea9 | `checkpubkey: base64_decode success` |
| 0x32ecc | `checkpubkey: compare failed` |
| 0x32ee8 | `checkpubkey: algo match failed` |
| 0x32f07 | `ssh-rsa` |
| 0x32f0f | `ecdsa-sha2-nistp256` |
| 0x32f23 | `ecdsa-sha2-nistp384` |
| 0x32f37 | `ecdsa-sha2-nistp521` |
| 0x32f5b | `rsa.c` |
| 0x32f61 | `rsa_EM->pos == rsa_EM->size` |
| 0x32f7d | `enter buf_get_rsa_pub_key` |
| 0x32f97 | `leave buf_get_rsa_pub_key: failure` |
| 0x32fba | `RSA key too short` |
| 0x32fcc | `RSA key bad e` |
| 0x32fda | `leave buf_get_rsa_pub_key: success` |
| 0x32ffd | `enter buf_get_rsa_priv_key` |
| 0x33018 | `leave buf_get_rsa_priv_key: pub: ret == DROPBEAR_FAILURE` |

### Key Code Sections (Capstone ARM Disassembly)

#### RSA Algorithm @ 0x32e6b
```asm
  0x00032e2b: mcrvs    p9, #3, r6, c7, c3, #3
  0x00032e2f: rsbhs    r6, r7, sb, ror #28
  0x00032e33: ldrbvs   r7, [r0, #-0x974]!
  0x00032e37: strbtvc  r6, [lr], #-0x500
  0x00032e3b: eorvs    r7, r0, #0x50000006
  0x00032e3f: usub16vc r6, pc, r5
  0x00032e43: strbtvs  r7, [sb], -r5, ror #4
  0x00032e47: svcvs    #0x4e0079
  0x00032e4b: cmppl    r3, #32, #8
  0x00032e4f: stmdbvc  r5!, {r5, r8, sb, fp, sp, lr} ^
  0x00032e53: rsbhs    r7, pc, r0, lsr #8
  0x00032e57: ldmdbvs  r2!, {r1, r2, r4, r5, r6, r8, sl, sp, lr} ^
```

#### Decrypt Function @ 0x33bfd
```asm
  0x00033bbd: ldmdbvs  r2!, {r5, r8, sb, sl, ip, sp, lr} ^
  0x00033bc1: subsvc   r6, pc, r4, ror r5
  0x00033bc5: strbvs   r6, [fp, #-0x361]!
  0x00033bc9: strmi    r3, [r0, #-0xa74]!
  0x00033bcd: subspl   r4, r4, #0x490
  0x00033bd1: rsbsvc   r4, r2, #0, #10
  0x00033bd5: strvc    r7, [r0, -pc, ror #4]!
  0x00033bd9: ldmdbvs  r4!, {r1, r4, r5, r6, r8, fp, sp, lr} ^
  0x00033bdd: eorshs   r6, sl, lr, ror #14
```

#### Encrypt Function @ 0x33d3d
```asm
  0x00033cfd: strbvs   r6, [lr, #-0xf64]!
```

#### Password Reference @ 0x361bb
```asm
  0x0003617b: strvc    r2, [r5, #-0x2c]!
```


## libhw_smp_cwmp_conabroad.so (17,396 bytes)
**MD5**: `2f57447e2ec1cce7db363fcbf1a78777`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x12b4

### Crypto-Related Strings (21)
| Offset | String |
|--------|--------|
| 0xa88 | `HW_CWMP_PrvtKeyRegSSMPAbroadRelation` |
| 0xaad | `HW_CWMP_PrvtKeyNoramlMaskRegSSMP_TELMEX` |
| 0xad5 | `HW_CWMP_PrvtKeyRegKeyMask` |
| 0xb2f | `CWMP_PrvtKeyTelefonicaSSMP` |
| 0xb4a | `HW_CWMP_PrvtKeyNoramlMaskRegSSMP` |
| 0xb6b | `HW_CWMP_PrvtSSMPAbroad` |
| 0xb9a | `HW_CWMP_PrvtKeyFtFilterCom` |
| 0xbc2 | `HW_CWMP_PrvtKeyMaskRegForIoT` |
| 0xd2d | `CWMP_PrvtKeyBztlfVIVOSSMP` |
| 0xd47 | `HW_CWMP_PrvtKeyRegAttRelation` |
| 0xd77 | `CWMP_PrvtKeyXDGlobe` |
| 0x2663 | `InternetGatewayDevice.WANDevice.1.X_3BB_GponInterfaceConfig.Stats.BytesReceived` |
| 0x27e3 | `InternetGatewayDevice.WANDevice.1.X_3BB_GponInterfaceConfig.Stats.PacketsReceive` |
| 0x2fee | `InternetGatewayDevice.LANConfigSecurity.ConfigPassword` |
| 0x3202 | `InternetGatewayDevice.WANDevice.1.X_3BB_GponInterfaceConfig.TransceiverTemperatu` |
| 0x335f | `HW_CWMP_PrvtSSMPAbroad Err[0x%x]` |
| 0x33bf | `InternetGatewayDevice.X_VIVO_COM_BR.AccessClass` |
| 0x33ef | `<CWMP>CWMP_PrvtKeyBztlfVIVOSSMP Err, uiRet=0x%x` |
| 0x344e | `<CWMP>CWMP_PrvtKeyXDGlobe Err, uiRet=0x%x` |
| 0x3516 | `hw_cwmp_privatekey_normal_ssmp.c` |
| 0x403e | `.gnu.hash` |

### Key Code Sections (Capstone ARM Disassembly)


## libhw_smp_cwmp_core.so (827,320 bytes)
**MD5**: `f8434ceac9c6c34c499a6de8e3ea1c60`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x25c08

### Crypto-Related Strings (323)
| Offset | String |
|--------|--------|
| 0xef24 | `CwmpDownLoadWebCert` |
| 0xef4f | `HW_CWMP_SignalHandle` |
| 0xf024 | `HW_CWMP_PrvtKeyRegKeyMask` |
| 0xf1cf | `HW_DM_GetEncryptedKey` |
| 0xf1fe | `HW_XML_CFGFileSecurityWithKey` |
| 0xf34a | `CwmpDownLoadTr069Cert` |
| 0xf816 | `HW_CWMP_RecordCertExpireLog` |
| 0xf84d | `HW_CWMP_CertTimeOutProc` |
| 0xf878 | `CWMP_GetSslCert` |
| 0xf888 | `CwmpFreeSslCerts` |
| 0xf899 | `HW_SSL_X509VerifyCertDate` |
| 0xf8b3 | `HW_CWMP_CheckCertValid` |
| 0xfa61 | `HW_CWMP_Get_LoadSslKeyWord` |
| 0xfaac | `HW_CWMP_InitParameterKey` |
| 0xfac5 | `HW_CWMP_InitDefaultUserNameAndPassword` |
| 0xfd6d | `CWMP_SmoothCertName` |
| 0xfdaa | `CWMP_RegSignal` |
| 0xfdb9 | `HW_OS_Signal` |
| 0x1032f | `HW_CWMP_GetPrvtnodeConvertFeatureState` |
| 0x10356 | `HW_CWMP_GetKeepAliveFeatureState` |
| 0x103c1 | `HW_CWMP_InitGetBoardinfo` |
| 0x103f1 | `g_stCwmpBoardinfo` |
| 0x10511 | `HW_CWMP_GetBoardinfoCfgWordIsNWTMode` |
| 0x10653 | `HW_CWMP_RPC_SetCertificateFlag` |
| 0x1078f | `HW_CWMP_RPC_CliLoadCert` |
| 0x10b5f | `HW_CWMP_RPC_SetUpdateCert` |
| 0x10b79 | `HW_CWMP_RPC_GetUpdateCert` |
| 0x10c77 | `HW_CWMP_RPC_PrvtKeyGetNCvtParaType` |
| 0x10d1c | `HW_PRVTNODE_SetGlobalList` |
| 0x10d4b | `HW_PRVTNODE_ProcListInit` |
| 0x10d64 | `HW_PRVTNODE_ProcListDeInit` |
| 0x10d8e | `HW_PRVTNODE_RegProc` |
| 0x10dc0 | `HW_PRVTNODE_GetAndExeProcs` |
| 0x110eb | `HW_CWMP_GetPrivateIndex` |
| 0x11197 | `HW_CWMP_PrvtKeyConvertStr` |
| 0x11212 | `HW_CWMP_PrvtKeyIsMask` |
| 0x112ab | `HW_CWMP_IsObjEndWithAliasHasTag` |
| 0x11369 | `HW_CWMP_GetKeyWord` |
| 0x11497 | `ATP_NET_SL_SetClientAuthMode` |
| 0x11510 | `CwmpGetSslRootCertDir` |
| 0x11573 | `HW_SSL_LoadCertFile` |
| 0x11833 | `CWMP_SetSocketKeepAlive` |
| 0x118dc | `SSP_PRIVILEGE_RaiseNetAdmin` |
| 0x118f8 | `SSP_PRIVILEGE_DropNetAdmin` |
| 0x119f3 | `ATP_NET_SL_SetCertEnable` |
| 0x11a24 | `ATP_NET_SL_GetCertEnable` |
| 0x11a3d | `ATP_NET_SL_SetCertPath` |
| 0x11a6d | `ATP_NET_HttpClientSaveAuth` |
| 0x11cd4 | `ATP_NET_HttpClientSetPassword` |
| 0x11cf2 | `ATP_NET_HttpClientSetCertEnable` |
| 0x11e10 | `HTTPAuth_BuildAuthorizationHeader` |
| 0x11ed7 | `ATP_NET_HttpClientGetAuthtype` |
| 0x11ef5 | `ATP_NET_HttpClientSetAuthtype` |
| 0x11fdc | `HttpServerGetAuthType` |
| 0x11ff2 | `HttpServerDoAuthrizationEx` |
| 0x1200d | `HTTPDigest_AuthRandomURI` |
| 0x12026 | `HTTPAuth_BuildChallengeHeader` |
| 0x12044 | `HTTPAuth_CheckAuthorization` |
| 0x120dc | `gstCwmpLoginInfo` |
| 0x12136 | `HW_CWMP_OnSrvLoginUnlock` |

### Key Code Sections (Capstone ARM Disassembly)

#### RSA Algorithm @ 0xad31c
```asm
  0x000ad2dc: eoreq    r2, lr, lr, lsr #20
  0x000ad2e0: smlsldpl r5, r8, r8, pc
  0x000ad2e4: strtpl   r3, [r0], -r0, lsl #8
  0x000ad2e8: ldrbmi   r4, [r5, #-0xc41]
```

#### Private Key Reference @ 0xa66c2
```asm
  0x000a6682: uqsub16vs r2, sl, r4
  0x000a6686: svchs    #0x327366
  0x000a668a: strbvs   r6, [sb, #-0xc63]!
  0x000a668e: strbvs   r7, [fp, #-0x46e]!
  0x000a6692: ldrbvs   r2, [r0, #-0xe79]!
  0x000a6696: strbtvc  r0, [sp], -sp, rrx
  0x000a669a: rsbhs    r2, r6, r0, lsr #26
  0x000a669e: strbtvc  r6, [lr], #-0xd2f
  0x000a66a2: strbtvs  r6, [r6], -pc, lsr #20
```

#### Decrypt Function @ 0xa6880
```asm
  0x000a6840: svcpl    #0x74706f
  0x000a6844: mrchs    p13, #3, r6, c0, c4, #3
  0x000a6848: rsbeq    r6, ip, r8, ror sp
  0x000a684c: cmppl    pc, #72, #14
  0x000a6850: svcpl    #0x504d53
  0x000a6854: strbpl   r4, [r1], #-0x546
  0x000a6858: svcpl    #0x455255
  0x000a685c: svcpl    #0x474643
  0x000a6860: blmi     #0x1176d70
  0x000a6864: blpl     #0xba9c0
  0x000a6868: ldmdapl  pc, {r3, r6, r8, sb, sl, ip, lr} ^
  0x000a686c: ldrbmi   r4, [pc], #-0xc4d
  0x000a6870: strbvs   r4, [r8, #-0x342]!
  0x000a6874: vldrmi   d22, [r8, #-0x18c]
  0x000a6878: stclvs   p6, c5, [r1], #-0x130
```

#### Encrypt Function @ 0xa68a9
```asm
  0x000a6869: ldclmi   p15, c5, [r8, #-0x15c]
  0x000a686d: submi    r5, r4, #76, #30
```

#### Password Reference @ 0xa8662
```asm
  0x000a8622: strbmi   r6, [lr, #-0xf69]!
  0x000a8626: mcrvs    p13, #0, r5, c0, c8, #3
  0x000a862a: strbvs   r2, [lr, #-0x6f]!
```

#### RSA Key Marker @ 0xad9bd
```asm
  0x000ad97d: blvs     #0x1986f25
  0x000ad981: stchs    p13, c2, [sp, #-0]!
  0x000ad985: strbmi   r2, [r2, #-0xd2d]
  0x000ad989: subhs    r4, lr, r7, asr #18
  0x000ad98d: ldrbpl   r4, [r2], #-0x543
  0x000ad991: movtmi   r4, #0x9649
  0x000ad995: stclhs   p4, c5, [r5, #-0x104]
  0x000ad999: stchs    p13, c2, [sp, #-0xb4]!
  0x000ad99d: stchs    p13, c2, [sp, #-0]!
  0x000ad9a1: cdpmi    p13, #4, c2, c5, c13, #1
  0x000ad9a5: strbmi   r2, [r3, #-0x44]
```


## libhw_smp_cwmp_conchina.so (97,072 bytes)
**MD5**: `0f2db53697389be79f37ec980eb74da7`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x53c4

### Crypto-Related Strings (140)
| Offset | String |
|--------|--------|
| 0x1d3b | `HW_CWMP_DummyNodeObj_Call_RegKeyRelation` |
| 0x1d9b | `HW_CWMP_PrvtKeyRegKeyMask` |
| 0x1e37 | `HW_CWMP_RegKeyRelation_CallBack_TJCU` |
| 0x1ec4 | `HW_CWMP_RegKeyRelation_CallBack_SDCU` |
| 0x205b | `HW_PRVTKEY_CONVERT_Inner` |
| 0x2081 | `HW_PRVTKEY_CONVERT_P_SPEEDTEST_BJCU` |
| 0x20a5 | `HW_PRVTKEY_CONVERT_N_SPEEDTEST_BJCU` |
| 0x20c9 | `HW_PRVTKEY_CONVERT_P_SPEEDTEST_TJCU` |
| 0x20ed | `HW_PRVTKEY_CONVERT_N_SPEEDTEST_TJCU` |
| 0x2158 | `HW_PRVTNODE_RegProc` |
| 0x216c | `HW_CWMP_PrvtKeyRegDummyNode` |
| 0x2188 | `HW_CWMP_RegKeyRelation_CallBack_BJCU` |
| 0x21ad | `HW_CWMP_PrvtKeyRegObjRelation` |
| 0x21cb | `HW_CWMP_PrvtKeyRegAttRelation` |
| 0x2233 | `HW_CWMP_ChangePrvtKeyList` |
| 0x224d | `CWMP_GetRmsSpeedPrvtKeyRelation` |
| 0x2284 | `HW_PRVTKEY_CONVERT_P_SPEEDTEST_SDCU` |
| 0x22a8 | `HW_PRVTKEY_CONVERT_N_SPEEDTEST_SDCU` |
| 0x22cc | `HW_CWMP_ChangeKeyValues` |
| 0x22e4 | `HW_CWMP_PrvKeyRegKeyE8C` |
| 0x232d | `HW_CWMP_PrvtKeyRegSSMPChinaRelation` |
| 0x2351 | `HW_CWMP_PrvtKeyChinaTelecomSSMP` |
| 0x2371 | `HW_CWMP_PrvtKeyChinaTelecomServiceManage` |
| 0x239a | `HW_CWMP_PrvtKeyCTMaskRegSSMP` |
| 0x23b7 | `HW_CWMP_PrvtKeyCTCOMSSMPRegDummyNode` |
| 0x23dc | `HW_CWMP_PrvtKetCMCCDateView` |
| 0x23f8 | `HW_CWMP_PrvtKetCTDateView` |
| 0x2412 | `HW_CWMP_PrvtKeyChinaUnicomSSMP` |
| 0x2431 | `HW_CWMP_PrvtKeyCUMaskRegSSMP` |
| 0x244e | `HW_CWMP_PrvtKeyCUSSMPRegDummyNode` |
| 0x2470 | `HW_CWMP_PrvtKeyNoramlMaskRegSSMP` |
| 0x2491 | `HW_CWMP_PrvtKeyRegKeyMaskGeneral` |
| 0x2523 | `HW_CWMP_PrvtSSMPChina` |
| 0x2551 | `HW_CWMP_PrvtKeyFtFilterCom` |
| 0x256c | `HW_CWMP_PrvtKeyFtFiltermSSMP` |
| 0x2589 | `HW_PRVTNODE_RegProcSSMP` |
| 0x25a1 | `HW_CWMP_PrvtKeyCMCCRMSMaskRegSSMP` |
| 0x25c3 | `HW_CWMP_PrvtKeyMaskRegForIoT` |
| 0x2643 | `HW_PRVTKEY_CONVERT_P_FTP` |
| 0x267c | `HW_PRVTKEY_CONVERT_N_FTP` |
| 0x2695 | `HW_PRVTKEY_CONVERT_P_Telnet` |
| 0x26d7 | `HW_PRVTKEY_CONVERT_N_Telnet` |
| 0x26f3 | `HW_PRVTKEY_CONVERT_P_Location` |
| 0x273b | `HW_PRVTKEY_CONVERT_N_Location` |
| 0x2863 | `HW_CWMP_PrvtGetPerform` |
| 0x2908 | `HW_PRVTKEY_CONVERT_P_N_Performance` |
| 0x29a3 | `HW_PRVTKEY_CONVERT_P_N_TeleComAccount` |
| 0x29f5 | `HW_PRVTKEY_CONVERT_InitUserInfo_Table` |
| 0x2a35 | `HW_PRVTKEY_CONVERT_P_UserInfo` |
| 0x2a6c | `HW_PRVTKEY_CONVERT_N_UserInfo` |
| 0x2a8a | `HW_PRVTKEY_CONVERT_P_N_SingleAttr` |
| 0x2aac | `HW_PRVTKEY_CONVERT_P_N_CMCCAccount` |
| 0x2acf | `HW_PRVTKEY_CONVERT_P_N_SXGDAccount` |
| 0x2b59 | `HW_CWMP_PrvtKeyDealQoeNode` |
| 0x2cf1 | `HW_CWMP_ProcessBztlfVIVOSSMPNode` |
| 0x2d34 | `HW_PRVTKEY_CONVERT_P_UNION_WEB` |
| 0x2dab | `HW_PRVTKEY_CONVERT_N_UNION_WEB` |
| 0x2dca | `HW_PRVTKEY_CONVERT_P_UNION_TELNET` |
| 0x2e20 | `HW_PRVTKEY_CONVERT_N_UNION_TELNET` |
| 0x2e42 | `HW_PRVTKEY_CONVERT_P_UNION_FTP` |

### Key Code Sections (Capstone ARM Disassembly)

#### Password Reference @ 0xf136
```asm
  0x0000f0f6: strbtvs  r6, [r5], #-0x570
  0x0000f0fa: ldrbtvc  r6, [r3], #-0x554
  0x0000f0fe: rsbsvc   r4, r5, lr, lsr #10
  0x0000f102: strbvs   r7, [pc, #-0x70]!
  0x0000f106: strbvs   r6, [sp, #-0x16e]!
  0x0000f10a: strbtvc  r4, [lr], #-0x900
  0x0000f10e: strbvs   r7, [lr, #-0x265]!
  0x0000f112: strbtvc  r4, [r1], #-0x774
  0x0000f116: stmdbvc  r1!, {r0, r2, r5, r6, r8, sb, sl, ip, sp, lr} ^
  0x0000f11a: ldmdbvs  r6!, {r2, r6, r8, sl, sp, lr} ^
  0x0000f11e: stmdapl  lr!, {r0, r1, r5, r6, r8, sl, sp, lr}
  0x0000f122: svcpl    #0x57485f
  0x0000f126: rsbsvc   r7, r4, r8, asr #8
  0x0000f12a: strbvs   r7, [r5, #-0x53]!
```


## libhw_smp_httpclient.so (95,588 bytes)
**MD5**: `c70a6722246f5b617cf31c2dc1094430`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x4aa4

### Crypto-Related Strings (36)
| Offset | String |
|--------|--------|
| 0x2305 | `HW_XmlJointAuthTicketBody` |
| 0x25c3 | `HTTPAuthor_ClientAuthor` |
| 0x25db | `HTTP_TcpCltReceive` |
| 0x26b6 | `HTTP_TcpCltReceiveIgnore` |
| 0x291c | `HTTP_AuthCopy` |
| 0x2995 | `WEB_SSL_SetCiphersuites` |
| 0x2a0e | `WEB_SSL_TLSCalcKey` |
| 0x2d3a | `__aeabi_uidivmod` |
| 0x2d4b | `HTTPAuthor_ParseField` |
| 0x2d71 | `HTTPAuthor_Calculate` |
| 0x2e80 | `SSP_PRIVILEGE_RaiseNetAdmin` |
| 0x2ead | `SSP_PRIVILEGE_DropNetAdmin` |
| 0x3151 | `g_uiReceivedSize` |
| 0x14284 | `[%s_%d]lAuthorStatus=%d,ulCredSendTimes=%d` |
| 0x14339 | `[%s_%d]lAuthorStatus=%d` |
| 0x14376 | `WWW-Authenticate` |
| 0x143d5 | `[%s_%d]ulRecv=%d,lAuthorStatus=%d,ulCredSendTimes=%d` |
| 0x1440c | `[%s_%d]StatusCode=%d,lRecvStatus=%d,lAuthorStatus=%d` |
| 0x14482 | `[%s_%d]lAuthorStatus=%d, bChunked=%d` |
| 0x14507 | `[%s_%d]receiveing...` |
| 0x1490b | `[%s_%d]bStartRecv=%d, bChunked=%d, ulReceivedSize=%d` |
| 0x1495d | `[%s_%d]ulReceivedSize=%d` |
| 0x14978 | `FIFO_END WWG&CH^KEY*6877@6877%5a` |
| 0x149c0 | `Keep-Alive` |
| 0x15028 | `PROXY-Authenticate` |
| 0x15047 | `Proxy-Authorization: Basic ` |
| 0x15063 | `auth` |
| 0x1506d | `MD5-sess` |
| 0x150a9 | `Proxy-Authorization: Digest username="%s", realm="%s"` |
| 0x15106 | `, nonce="%s"` |
| 0x15129 | `, cnonce="%s"` |
| 0x15147 | `hw_http_clientauth.c` |
| 0x1516d | `cnonce` |
| 0x15b80 | `keep-alive` |
| 0x15cc3 | `[%s_%d]g_uiMaxBufferSize:%d, g_uiReceivedSize:%d, uiResponseInfoLen:%d` |
| 0x171ae | `.gnu.hash` |

### Key Code Sections (Capstone ARM Disassembly)


## libmbedcrypto.so.0 (407,220 bytes)
**MD5**: `037bf2b5fb0578b69fb899cd99b32202`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x10540

### Crypto-Related Strings (912)
| Offset | String |
|--------|--------|
| 0x6915 | `__aeabi_idivmod` |
| 0x695f | `mbedtls_aes_init` |
| 0x6977 | `mbedtls_aes_free` |
| 0x69a1 | `mbedtls_aes_setkey_enc` |
| 0x69b8 | `mbedtls_aes_setkey_dec` |
| 0x69cf | `mbedtls_internal_aes_encrypt` |
| 0x69ec | `mbedtls_aes_encrypt` |
| 0x6a00 | `mbedtls_internal_aes_decrypt` |
| 0x6a1d | `mbedtls_aes_decrypt` |
| 0x6a31 | `mbedtls_aes_crypt_ecb` |
| 0x6a47 | `mbedtls_aes_crypt_cbc` |
| 0x6a5d | `mbedtls_aes_crypt_cfb128` |
| 0x6a76 | `mbedtls_aes_crypt_cfb8` |
| 0x6a8d | `mbedtls_aes_crypt_ctr` |
| 0x6eeb | `mbedtls_mpi_safe_cond_assign` |
| 0x70d4 | `__aeabi_uldivmod` |
| 0x70e5 | `mbedtls_mpi_div_mpi` |
| 0x70f9 | `mbedtls_mpi_div_int` |
| 0x7121 | `__aeabi_uidivmod` |
| 0x7245 | `mbedtls_blowfish_setkey` |
| 0x72f7 | `mbedtls_camellia_setkey_enc` |
| 0x7313 | `mbedtls_camellia_setkey_dec` |
| 0x739e | `mbedtls_cipher_update` |
| 0x73c5 | `mbedtls_ccm_setkey` |
| 0x73d8 | `mbedtls_cipher_info_from_values` |
| 0x73f8 | `mbedtls_cipher_free` |
| 0x740c | `mbedtls_cipher_setup` |
| 0x7421 | `mbedtls_cipher_setkey` |
| 0x7448 | `mbedtls_ccm_star_encrypt_and_tag` |
| 0x7469 | `mbedtls_ccm_encrypt_and_tag` |
| 0x7485 | `mbedtls_ccm_star_auth_decrypt` |
| 0x74a3 | `mbedtls_ccm_auth_decrypt` |
| 0x74bc | `mbedtls_cipher_list` |
| 0x74d0 | `mbedtls_cipher_supported` |
| 0x74e9 | `mbedtls_cipher_definitions` |
| 0x7504 | `mbedtls_cipher_info_from_type` |
| 0x7522 | `mbedtls_cipher_info_from_string` |
| 0x7549 | `mbedtls_cipher_init` |
| 0x755d | `mbedtls_cipher_set_iv` |
| 0x7573 | `mbedtls_cipher_reset` |
| 0x7588 | `mbedtls_cipher_update_ad` |
| 0x75c7 | `mbedtls_cipher_finish` |
| 0x75dd | `mbedtls_cipher_set_padding_mode` |
| 0x75fd | `mbedtls_cipher_write_tag` |
| 0x7629 | `mbedtls_cipher_check_tag` |
| 0x7642 | `mbedtls_cipher_crypt` |
| 0x7657 | `mbedtls_cipher_auth_encrypt` |
| 0x768d | `mbedtls_cipher_auth_decrypt` |
| 0x76a9 | `mbedtls_gcm_auth_decrypt` |
| 0x76e6 | `mbedtls_des3_set3key_dec` |
| 0x76ff | `mbedtls_des3_set3key_enc` |
| 0x7746 | `mbedtls_des3_set2key_dec` |
| 0x775f | `mbedtls_des3_set2key_enc` |
| 0x779a | `mbedtls_des_setkey_dec` |
| 0x77b1 | `mbedtls_des_setkey_enc` |
| 0x7816 | `mbedtls_gcm_setkey` |
| 0x7829 | `mbedtls_cipher_cmac_starts` |
| 0x7844 | `__aeabi_uidiv` |
| 0x7852 | `mbedtls_cipher_cmac_update` |
| 0x786d | `mbedtls_cipher_cmac_finish` |

### Key Code Sections (Capstone ARM Disassembly)

#### AES Algorithm @ 0x536a4

#### RSA Algorithm @ 0x5496a
```asm
  0x0005492a: ldmdbvs  r2!, {r0, r1, r4, r5, r6, sl, ip, sp, lr} ^
  0x0005492e: stmdbvs  r0!, {r1, r2, r3, r5, r6, r8, sb, sl, sp, lr}
  0x00054932: svcvs    #0x6e2073
```

#### Decrypt Function @ 0x6a15
```asm
  0x000069d5: mcrvs    p15, #3, r5, c9, c3, #3
  0x000069d9: mrcvs    p5, #3, r6, c2, c4, #3
  0x000069dd: cmpvs    pc, r1, ror #24
  0x000069e1: ldrbvs   r7, [pc, #-0x365]
  0x000069e5: ldmdbvc  r2!, {r1, r2, r3, r5, r6, r8, sb, sp, lr} ^
  0x000069e9: stcvs    p4, c7, [r0, #-0x1c0]
  0x000069ed: strbtvc  r6, [r4], #-0x562
  0x000069f1: cmpvs    pc, ip, ror #6
  0x000069f5: ldrbvs   r7, [pc, #-0x365]
  0x000069f9: ldmdbvc  r2!, {r1, r2, r3, r5, r6, r8, sb, sp, lr} ^
  0x000069fd: stcvs    p4, c7, [r0, #-0x1c0]
  0x00006a01: strbtvc  r6, [r4], #-0x562
  0x00006a05: ldmdbvs  pc, {r2, r3, r5, r6, r8, sb, ip, sp, lr} ^
  0x00006a09: rsbvc    r7, r5, #0x6e000000
  0x00006a0d: svcpl    #0x6c616e
```

#### Encrypt Function @ 0x69e4

#### Password Reference @ 0x549c3
```asm
  0x00054983: andpl    r7, r0, r1, ror #8
  0x00054987: stchs    p13, c4, [r0, #-0x114]!
```

#### RSA Key Marker @ 0x57c0e
```asm
  0x00057bce: cdpgt    p6, #4, c8, c8, c10, #1
  0x00057bd2: andeq    r0, r1, sp, lsr r1
  0x00057bd6: strbhi   r8, [r8], -sl, lsr #12
```


## libwlan_aes_crypto.so (5,012 bytes)
**MD5**: `4892cf1719c5185c1964383e47174ce5`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x4f0

### Crypto-Related Strings (9)
| Offset | String |
|--------|--------|
| 0x2a0 | `WLAN_AES_Cbc_128_Encrypt` |
| 0x301 | `polarssl_aes_init` |
| 0x313 | `polarssl_aes_setkey_enc` |
| 0x33a | `polarssl_aes_crypt_cbc` |
| 0x37a | `WLAN_AES_Cbc_128_Decrypt` |
| 0x393 | `polarssl_aes_setkey_dec` |
| 0x3ab | `libwlan_aes_crypto.so` |
| 0x7d4 | `wlan_aes_crypto.c` |
| 0x103a | `.gnu.hash` |

### Key Code Sections (Capstone ARM Disassembly)

#### AES Algorithm @ 0x2a5


## libmbedcrypto.so (407,220 bytes)
**MD5**: `037bf2b5fb0578b69fb899cd99b32202`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x10540

### Crypto-Related Strings (912)
| Offset | String |
|--------|--------|
| 0x6915 | `__aeabi_idivmod` |
| 0x695f | `mbedtls_aes_init` |
| 0x6977 | `mbedtls_aes_free` |
| 0x69a1 | `mbedtls_aes_setkey_enc` |
| 0x69b8 | `mbedtls_aes_setkey_dec` |
| 0x69cf | `mbedtls_internal_aes_encrypt` |
| 0x69ec | `mbedtls_aes_encrypt` |
| 0x6a00 | `mbedtls_internal_aes_decrypt` |
| 0x6a1d | `mbedtls_aes_decrypt` |
| 0x6a31 | `mbedtls_aes_crypt_ecb` |
| 0x6a47 | `mbedtls_aes_crypt_cbc` |
| 0x6a5d | `mbedtls_aes_crypt_cfb128` |
| 0x6a76 | `mbedtls_aes_crypt_cfb8` |
| 0x6a8d | `mbedtls_aes_crypt_ctr` |
| 0x6eeb | `mbedtls_mpi_safe_cond_assign` |
| 0x70d4 | `__aeabi_uldivmod` |
| 0x70e5 | `mbedtls_mpi_div_mpi` |
| 0x70f9 | `mbedtls_mpi_div_int` |
| 0x7121 | `__aeabi_uidivmod` |
| 0x7245 | `mbedtls_blowfish_setkey` |
| 0x72f7 | `mbedtls_camellia_setkey_enc` |
| 0x7313 | `mbedtls_camellia_setkey_dec` |
| 0x739e | `mbedtls_cipher_update` |
| 0x73c5 | `mbedtls_ccm_setkey` |
| 0x73d8 | `mbedtls_cipher_info_from_values` |
| 0x73f8 | `mbedtls_cipher_free` |
| 0x740c | `mbedtls_cipher_setup` |
| 0x7421 | `mbedtls_cipher_setkey` |
| 0x7448 | `mbedtls_ccm_star_encrypt_and_tag` |
| 0x7469 | `mbedtls_ccm_encrypt_and_tag` |
| 0x7485 | `mbedtls_ccm_star_auth_decrypt` |
| 0x74a3 | `mbedtls_ccm_auth_decrypt` |
| 0x74bc | `mbedtls_cipher_list` |
| 0x74d0 | `mbedtls_cipher_supported` |
| 0x74e9 | `mbedtls_cipher_definitions` |
| 0x7504 | `mbedtls_cipher_info_from_type` |
| 0x7522 | `mbedtls_cipher_info_from_string` |
| 0x7549 | `mbedtls_cipher_init` |
| 0x755d | `mbedtls_cipher_set_iv` |
| 0x7573 | `mbedtls_cipher_reset` |
| 0x7588 | `mbedtls_cipher_update_ad` |
| 0x75c7 | `mbedtls_cipher_finish` |
| 0x75dd | `mbedtls_cipher_set_padding_mode` |
| 0x75fd | `mbedtls_cipher_write_tag` |
| 0x7629 | `mbedtls_cipher_check_tag` |
| 0x7642 | `mbedtls_cipher_crypt` |
| 0x7657 | `mbedtls_cipher_auth_encrypt` |
| 0x768d | `mbedtls_cipher_auth_decrypt` |
| 0x76a9 | `mbedtls_gcm_auth_decrypt` |
| 0x76e6 | `mbedtls_des3_set3key_dec` |
| 0x76ff | `mbedtls_des3_set3key_enc` |
| 0x7746 | `mbedtls_des3_set2key_dec` |
| 0x775f | `mbedtls_des3_set2key_enc` |
| 0x779a | `mbedtls_des_setkey_dec` |
| 0x77b1 | `mbedtls_des_setkey_enc` |
| 0x7816 | `mbedtls_gcm_setkey` |
| 0x7829 | `mbedtls_cipher_cmac_starts` |
| 0x7844 | `__aeabi_uidiv` |
| 0x7852 | `mbedtls_cipher_cmac_update` |
| 0x786d | `mbedtls_cipher_cmac_finish` |

### Key Code Sections (Capstone ARM Disassembly)

#### AES Algorithm @ 0x536a4

#### RSA Algorithm @ 0x5496a
```asm
  0x0005492a: ldmdbvs  r2!, {r0, r1, r4, r5, r6, sl, ip, sp, lr} ^
  0x0005492e: stmdbvs  r0!, {r1, r2, r3, r5, r6, r8, sb, sl, sp, lr}
  0x00054932: svcvs    #0x6e2073
```

#### Decrypt Function @ 0x6a15
```asm
  0x000069d5: mcrvs    p15, #3, r5, c9, c3, #3
  0x000069d9: mrcvs    p5, #3, r6, c2, c4, #3
  0x000069dd: cmpvs    pc, r1, ror #24
  0x000069e1: ldrbvs   r7, [pc, #-0x365]
  0x000069e5: ldmdbvc  r2!, {r1, r2, r3, r5, r6, r8, sb, sp, lr} ^
  0x000069e9: stcvs    p4, c7, [r0, #-0x1c0]
  0x000069ed: strbtvc  r6, [r4], #-0x562
  0x000069f1: cmpvs    pc, ip, ror #6
  0x000069f5: ldrbvs   r7, [pc, #-0x365]
  0x000069f9: ldmdbvc  r2!, {r1, r2, r3, r5, r6, r8, sb, sp, lr} ^
  0x000069fd: stcvs    p4, c7, [r0, #-0x1c0]
  0x00006a01: strbtvc  r6, [r4], #-0x562
  0x00006a05: ldmdbvs  pc, {r2, r3, r5, r6, r8, sb, ip, sp, lr} ^
  0x00006a09: rsbvc    r7, r5, #0x6e000000
  0x00006a0d: svcpl    #0x6c616e
```

#### Encrypt Function @ 0x69e4

#### Password Reference @ 0x549c3
```asm
  0x00054983: andpl    r7, r0, r1, ror #8
  0x00054987: stchs    p13, c4, [r0, #-0x114]!
```

#### RSA Key Marker @ 0x57c0e
```asm
  0x00057bce: cdpgt    p6, #4, c8, c8, c10, #1
  0x00057bd2: andeq    r0, r1, sp, lsr r1
  0x00057bd6: strbhi   r8, [r8], -sl, lsr #12
```


## libcrypto.so.1.0.0 (1,884,456 bytes)
**MD5**: `97526c8dae13462b202030f98aa4cfad`
**Architecture**: ARM (32-bit, little endian)
**Entry point**: 0x4f560

### Crypto-Related Strings (2717)
| Offset | String |
|--------|--------|
| 0x23a0b | `AES_cbc_encrypt` |
| 0x23a1b | `CRYPTO_cbc128_encrypt` |
| 0x23a31 | `CRYPTO_cbc128_decrypt` |
| 0x23a47 | `AES_encrypt` |
| 0x23a53 | `AES_decrypt` |
| 0x23a5f | `AES_cfb128_encrypt` |
| 0x23a72 | `CRYPTO_cfb128_encrypt` |
| 0x23a88 | `AES_cfb1_encrypt` |
| 0x23a99 | `CRYPTO_cfb128_1_encrypt` |
| 0x23ab1 | `AES_cfb8_encrypt` |
| 0x23ac2 | `CRYPTO_cfb128_8_encrypt` |
| 0x23ada | `AES_set_encrypt_key` |
| 0x23aee | `AES_set_decrypt_key` |
| 0x23b02 | `AES_ecb_encrypt` |
| 0x23b12 | `AES_ige_encrypt` |
| 0x23b51 | `AES_bi_ige_encrypt` |
| 0x23b64 | `AES_options` |
| 0x23b70 | `AES_ofb128_encrypt` |
| 0x23b83 | `CRYPTO_ofb128_encrypt` |
| 0x23b99 | `AES_wrap_key` |
| 0x23bb6 | `AES_unwrap_key` |
| 0x23f02 | `BN_is_negative` |
| 0x23f4e | `BN_set_negative` |
| 0x241d1 | `BN_div_word` |
| 0x242da | `ASN1_UNIVERSALSTRING_to_string` |
| 0x2430b | `ASN1_sign` |
| 0x24363 | `EVP_PKEY_size` |
| 0x24394 | `EVP_SignFinal` |
| 0x243a2 | `ASN1_item_sign_ctx` |
| 0x243c3 | `EVP_MD_CTX_pkey_ctx` |
| 0x243d7 | `EVP_PKEY_CTX_get0_pkey` |
| 0x24421 | `EVP_DigestSign` |
| 0x24430 | `ASN1_item_sign` |
| 0x2443f | `EVP_DigestSignInit` |
| 0x24996 | `EVP_PKEY_type` |
| 0x249ca | `EVP_PKEY_asn1_get_count` |
| 0x249f1 | `EVP_PKEY_asn1_get0` |
| 0x24a04 | `EVP_PKEY_asn1_find` |
| 0x24a17 | `ENGINE_get_pkey_asn1_meth_engine` |
| 0x24a38 | `ENGINE_get_pkey_asn1_meth` |
| 0x24a52 | `EVP_PKEY_asn1_find_str` |
| 0x24a69 | `ENGINE_pkey_asn1_find_str` |
| 0x24aa7 | `EVP_PKEY_asn1_add0` |
| 0x24aca | `EVP_PKEY_asn1_get0_info` |
| 0x24ae2 | `EVP_PKEY_get0_asn1` |
| 0x24af5 | `EVP_PKEY_asn1_copy` |
| 0x24b08 | `EVP_PKEY_asn1_free` |
| 0x24b1b | `EVP_PKEY_asn1_new` |
| 0x24b3b | `EVP_PKEY_asn1_add_alias` |
| 0x24b53 | `EVP_PKEY_asn1_set_public` |
| 0x24b6c | `EVP_PKEY_asn1_set_private` |
| 0x24b86 | `EVP_PKEY_asn1_set_param` |
| 0x24b9e | `EVP_PKEY_asn1_set_free` |
| 0x24bb5 | `EVP_PKEY_asn1_set_ctrl` |
| 0x24bcc | `EVP_PKEY_asn1_set_security_bits` |
| 0x24bec | `EVP_PKEY_asn1_set_item` |
| 0x24c03 | `EVP_PKEY_asn1_set_siginf` |
| 0x24c1c | `EVP_PKEY_asn1_set_check` |
| 0x24c34 | `EVP_PKEY_asn1_set_public_check` |
| 0x24c53 | `EVP_PKEY_asn1_set_param_check` |

### Key Code Sections (Capstone ARM Disassembly)

#### AES Algorithm @ 0x23a0b
```asm
  0x000239cb: svcpl    #0x656c
  0x000239cf: cmnvs    r8, pc, asr r3
  0x000239d3: mcrvs    p6, #3, r6, c9, c15, #2
  0x000239d7: bvc      #0x1a7eb63
  0x000239db: svcpl    #0x5f0065
  0x000239df: ldrbvs   r6, [r2, #-0x564]!
  0x000239e3: ldrbtvc  r6, [r3], #-0x967
  0x000239e7: ldrbvs   r7, [pc], -r5, ror #4
  0x000239eb: strbvs   r6, [sp, #-0x172]!
  0x000239ef: uqsaxvs  r6, lr, pc
  0x000239f3: svcpl    #0x5f006f
  0x000239f7: stmdbvs  r7!, {r1, r4, r5, r6, r8, sl, sp, lr} ^
  0x000239fb: rsbvc    r7, r5, #0x73000000
  0x000239ff: cmnvs    r2, pc, asr r6
  0x00023a03: ldmdbvs  pc, {r0, r2, r3, r5, r6, r8, sl, sp, lr} ^
```

#### RSA Algorithm @ 0x242e4
```asm
  0x000242a4: subspl   r5, r4, #0x7c000001
  0x000242a8: svcpl    #0x474e49
  0x000242ac: rsbseq   r6, r0, r3, ror #26
```

#### Decrypt Function @ 0x23a3f
```asm
  0x000239ff: cmnvs    r2, pc, asr r6
  0x00023a03: ldmdbvs  pc, {r0, r2, r3, r5, r6, r8, sl, sp, lr} ^
  0x00023a07: rsbeq    r6, pc, lr, ror #12
  0x00023a0b: svcpl    #0x534541
  0x00023a0f: svcpl    #0x636263
  0x00023a13: rsbvc    r6, r3, #0x650
  0x00023a17: rsbseq   r7, r4, sb, ror r0
  0x00023a1b: subspl   r5, sb, r3, asr #4
  0x00023a1f: cmpvs    pc, #84, #30
  0x00023a23: eorslo   r6, r1, #0x88000001
  0x00023a27: mcrvs    p15, #3, r5, c5, c8, #1
  0x00023a2b: rsbsvc   r7, sb, r3, ror #4
  0x00023a2f: subpl    r0, r3, #0x74
  0x00023a33: svcmi    #0x545059
```

#### Encrypt Function @ 0x23a13
```asm
  0x000239d3: mcrvs    p6, #3, r6, c9, c15, #2
  0x000239d7: bvc      #0x1a7eb63
  0x000239db: svcpl    #0x5f0065
  0x000239df: ldrbvs   r6, [r2, #-0x564]!
  0x000239e3: ldrbtvc  r6, [r3], #-0x967
  0x000239e7: ldrbvs   r7, [pc], -r5, ror #4
  0x000239eb: strbvs   r6, [sp, #-0x172]!
  0x000239ef: uqsaxvs  r6, lr, pc
  0x000239f3: svcpl    #0x5f006f
  0x000239f7: stmdbvs  r7!, {r1, r4, r5, r6, r8, sl, sp, lr} ^
  0x000239fb: rsbvc    r7, r5, #0x73000000
  0x000239ff: cmnvs    r2, pc, asr r6
  0x00023a03: ldmdbvs  pc, {r0, r2, r3, r5, r6, r8, sl, sp, lr} ^
  0x00023a07: rsbeq    r6, pc, lr, ror #12
  0x00023a0b: svcpl    #0x534541
```

#### Password Reference @ 0x29353
```asm
  0x00029313: ldrblo   r0, [r8, #-0x72]
  0x00029317: smmlarvs pc, r0, sb, r3
  0x0002931b: svcpl    #0x307465
  0x0002931f: bvs      #0x18c68f3
  0x00029323: svcpl    #0x746365
  0x00029327: svcpl    #0x79656b
  0x0002932b: stmdapl  r0, {r0, r3, r5, r6, sl, sp, lr}
  0x0002932f: svcpl    #0x393035
  0x00029333: strbmi   r4, [sp, #-0x14e]
  0x00029337: strbtvc  r7, [r5], #-0x35f
  0x0002933b: movtpl   r4, #0xd300
```
