/*
 * hw_ssp_aescrypt.h  –  Huawei SSP AES-crypt API
 *
 * Reconstructed from libhw_ssp_basic.so exported symbols
 * (EG8145V5-V500R022C00SPC340B019 rootfs SquashFS, ARM32 Cortex-A9, musl libc).
 *
 * Symbols present in libhw_ssp_basic.so (.dynsym):
 *   OS_AescryptCRC       @ 0x62e78  size 108
 *   OS_AescryptFillHead  @ 0x63234  size 360
 *   OS_AescryptEncrypt   @ 0x6339c  size 380
 *   OS_AescryptDecrypt   @ 0x63744  size 460
 *   HW_SSL_AesCryptEcb   @ 0x61ab0  size  84
 *   HW_SSL_AesCryptCbc   @ 0x61b04  size  92
 *   SSL_AesCrypt         @ 0x61b60  size 152
 *
 * AES key derivation (device-unique, NOT stored in this binary):
 *   e-fuse root key → work key (flash keyfile partition) → AES-256-CBC.
 *
 * Encrypted-file header layout (written by OS_AescryptFillHead):
 *   Offset  Size  Description
 *   0x00     4    Format version  (observed: 0x04)
 *   0x04     4    Mode / flags    (observed: 0x01 = encrypted)
 *   0x08    16    AES-CBC IV (random)
 *   0x18     ?    AES-CBC ciphertext (PKCS#7-padded plain-text)
 *   last 4   4    CRC32 of header + ciphertext (OS_AescryptCRC)
 */

#ifndef HW_SSP_AESCRYPT_H
#define HW_SSP_AESCRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Encrypted-file header ─────────────────────────────────────────────── */

#define AESCRYPT_MAGIC_VERSION  0x04u
#define AESCRYPT_FLAG_ENCRYPTED 0x01u
#define AESCRYPT_IV_LEN         16u
#define AESCRYPT_HEADER_LEN     24u   /* version(4) + flags(4) + IV(16) */

typedef struct {
    uint32_t version;           /* 0x04 */
    uint32_t flags;             /* 0x01 when encrypted */
    uint8_t  iv[AESCRYPT_IV_LEN];
} HW_AescryptHeader;

/* ── Low-level AES helpers (libhw_ssp_basic.so) ────────────────────────── */

/**
 * OS_AescryptCRC – rolling CRC-32 (custom Huawei polynomial table).
 *
 * @param crc_init  Initial CRC value (0 for first block).
 * @param data      Pointer to input data.
 * @param len       Number of bytes to process.
 * @return          Updated CRC-32 value.
 */
uint32_t OS_AescryptCRC(uint32_t crc_init, const uint8_t *data, uint32_t len);

/**
 * OS_AescryptFillHead – build the 24-byte encrypted-file header.
 *
 * Generates a fresh random IV, writes version/flags/IV into the header
 * buffer, and stores a pointer to the buffer for the caller.
 *
 * @param out_hdr   Pointer to a buffer of at least AESCRYPT_HEADER_LEN bytes.
 * @param key_buf   Key material buffer (from MemGetRootKeyCfg chain).
 * @param iv_out    If non-NULL, receives a copy of the generated IV.
 * @return          0 on success, non-zero on error.
 */
int OS_AescryptFillHead(uint8_t *out_hdr, const uint8_t *key_buf,
                        uint8_t *iv_out);

/**
 * OS_AescryptEncrypt – encrypt a file using AES-256-CBC.
 *
 * The output file begins with a HW_AescryptHeader followed by the
 * PKCS#7-padded ciphertext and a trailing CRC-32 dword.
 *
 * @param unused    Reserved; callers pass 1.
 * @param infile    Path to the plaintext input file.
 * @param outfile   Path to the ciphertext output file.
 * @param arg4      Optional extra string argument (may be NULL).
 * @param has_arg5  Non-zero when a 5th argv was supplied.
 * @return          0 on success, non-zero error code on failure.
 */
int OS_AescryptEncrypt(int unused, const char *infile, const char *outfile,
                       const char *arg4, int has_arg5);

/**
 * OS_AescryptDecrypt – decrypt a file produced by OS_AescryptEncrypt.
 *
 * Reads the header, derives the device-bound key via the SSP key chain,
 * decrypts with AES-256-CBC and writes the plaintext file.
 *
 * @param unused    Reserved; callers pass 1.
 * @param infile    Path to the ciphertext input file.
 * @param outfile   Path to the plaintext output file.
 * @param arg4      Optional extra string argument (may be NULL).
 * @param has_arg5  Non-zero when a 5th argv was supplied.
 * @return          0 on success, non-zero error code on failure.
 */
int OS_AescryptDecrypt(int unused, const char *infile, const char *outfile,
                       const char *arg4, int has_arg5);

/* ── ECB / CBC wrappers (libhw_ssp_basic.so) ───────────────────────────── */

/**
 * HW_SSL_AesCryptEcb – single AES-ECB block operation.
 *
 * Thin dispatch shim: looks up the concrete function pointer via an
 * internal table (MemGetMkInfoByContent) and tail-calls it.
 *
 * @param key       AES key buffer (16/24/32 bytes depending on key_bits).
 * @param key_bits  Key length in bits: 128, 192, or 256.
 * @param mode      AES_ENCRYPT (1) or AES_DECRYPT (0).
 * @param input     16-byte input block.
 * @return          0 on success.
 */
int HW_SSL_AesCryptEcb(const uint8_t *key, uint32_t key_bits,
                        int mode, const uint8_t *input);

/**
 * HW_SSL_AesCryptCbc – AES-CBC multi-block operation.
 *
 * @param key       AES key buffer.
 * @param key_bits  Key length in bits.
 * @param mode      AES_ENCRYPT (1) or AES_DECRYPT (0).
 * @param input     Input plaintext/ciphertext.
 * @param iv        16-byte IV; updated in-place after the call.
 * @param output    Output buffer (same length as input).
 * @return          0 on success.
 */
int HW_SSL_AesCryptCbc(const uint8_t *key, uint32_t key_bits,
                        int mode, const uint8_t *input,
                        uint8_t *iv, uint8_t *output);

/**
 * SSL_AesCrypt – generic AES wrapper used by higher-level Huawei modules.
 *
 * Delegates to HW_SSL_AesCryptCbc after resolving the key via
 * MemGetMkInfoByContent; returns 1 on error (key lookup failure).
 */
int SSL_AesCrypt(const uint8_t *key, uint32_t key_bits,
                 int mode, const uint8_t *input,
                 uint8_t *iv, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* HW_SSP_AESCRYPT_H */
