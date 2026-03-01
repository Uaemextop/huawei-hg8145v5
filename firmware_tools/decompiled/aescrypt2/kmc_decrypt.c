/*
 * kmc_decrypt.c  –  Offline KMC key derivation and AEST file decryption.
 *
 * Reads kmc_store_A / kmc_store_B files extracted from firmware rootfs
 * (/etc/wap/kmc_store_{A,B}) and attempts to derive AES-256 keys for
 * decrypting hw_ctree.xml and other AEST-format files.
 *
 * The KMC (Key Management Center) store is a 2592-byte binary blob
 * containing timestamped key material managed by HW_KMC_GetActiveKey
 * and HW_KMC_GetAppointKey in libhw_ssp_basic.so.
 *
 * Key derivation chain:
 *   kmc_store → salt (first 32B) + material (at +0x20, 32B)
 *     → PBKDF2-HMAC-SHA256(material, salt, 1 iter, 32 bytes)
 *     → AES-256 key
 *     → OS_AescryptDecrypt (AEST format: version=4, flags=1, IV[16])
 *
 * Usage:
 *   kmc_decrypt <kmc_store_file> <encrypted_xml> <output_xml>
 *   kmc_decrypt --scan <kmc_store_file>   (dump key candidates)
 *
 * Build:
 *   gcc -DHAVE_MBEDTLS -I../stubs -o kmc_decrypt kmc_decrypt.c \
 *       ../aescrypt2/hw_ssp_aescrypt.c ../efuse/dm_key.c \
 *       ../stubs/hw_os_stubs.c -lmbedcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../aescrypt2/hw_ssp_aescrypt.h"
#include "../efuse/dm_key.h"

/* ── KMC store layout (from disassembly of HW_KMC_GetActiveKey) ──────── */
#define KMC_STORE_SIZE     2592u
#define KMC_HEADER_LEN      32u   /* first 32 bytes: store identifier */
#define KMC_MATERIAL_OFF     32u   /* material at +0x20 */
#define KMC_MATERIAL_LEN     32u   /* 32 bytes key material */
#define KMC_KEY_REGION_LEN   96u   /* flash head struct size */

/* Max candidate keys to try */
#define MAX_CANDIDATES 32

/* ── Forward declarations ───────────────────────────────────────────────── */
static int  read_file(const char *path, uint8_t **out, size_t *out_len);
static int  write_file(const char *path, const uint8_t *data, size_t len);
static int  try_aest_decrypt(const uint8_t *data, size_t len,
                              const uint8_t *key, uint8_t **out, size_t *out_len);

#if defined(HAVE_MBEDTLS)
#include <mbedtls/aes.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>

static int pbkdf2_derive(const uint8_t *material, size_t mat_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t *out_key, size_t key_len)
{
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret;

    mbedtls_md_init(&md_ctx);
    ret = mbedtls_md_setup(&md_ctx, md_info, 1);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(
                &md_ctx,
                material, mat_len,
                salt, salt_len,
                1,  /* iterations */
                (uint32_t)key_len,
                out_key);
    }
    mbedtls_md_free(&md_ctx);
    return ret;
}

static int aes_cbc_decrypt(const uint8_t *ct, size_t ct_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *iv,
                            uint8_t *out)
{
    mbedtls_aes_context ctx;
    uint8_t iv_copy[16];
    int ret;

    memcpy(iv_copy, iv, 16);
    mbedtls_aes_init(&ctx);
    ret = mbedtls_aes_setkey_dec(&ctx, key, (unsigned int)(key_len * 8));
    if (ret == 0)
        ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT,
                                     ct_len, iv_copy, ct, out);
    mbedtls_aes_free(&ctx);
    return ret;
}
#endif /* HAVE_MBEDTLS */

/* ── Derive candidate keys from KMC store ─────────────────────────────── */
static int derive_kmc_candidates(const uint8_t *kmc_data, size_t kmc_len,
                                  uint8_t candidates[][32], int max_cand)
{
    int count = 0;

#if !defined(HAVE_MBEDTLS)
    fprintf(stderr, "[!] mbedTLS not available, cannot derive keys\n");
    return 0;
#else
    if (kmc_len < KMC_HEADER_LEN + KMC_MATERIAL_LEN) {
        fprintf(stderr, "[!] KMC store too small: %zu bytes\n", kmc_len);
        return 0;
    }

    /* Candidate 1: PBKDF2(material[32:64], salt=header[0:32]) */
    if (count < max_cand) {
        pbkdf2_derive(kmc_data + KMC_MATERIAL_OFF, KMC_MATERIAL_LEN,
                       kmc_data, KMC_HEADER_LEN,
                       candidates[count], 32);
        count++;
    }

    /* Candidate 2: PBKDF2(header[0:32], salt=material[32:64]) */
    if (count < max_cand) {
        pbkdf2_derive(kmc_data, KMC_HEADER_LEN,
                       kmc_data + KMC_MATERIAL_OFF, KMC_MATERIAL_LEN,
                       candidates[count], 32);
        count++;
    }

    /* Candidate 3: Raw first 32 bytes as key */
    if (count < max_cand) {
        memcpy(candidates[count], kmc_data, 32);
        count++;
    }

    /* Candidate 4: Raw bytes [32:64] as key */
    if (count < max_cand && kmc_len >= 64) {
        memcpy(candidates[count], kmc_data + 32, 32);
        count++;
    }

    /* Candidate 5: PBKDF2 with all-zeros salt */
    if (count < max_cand) {
        uint8_t zero_salt[32];
        memset(zero_salt, 0, sizeof(zero_salt));
        pbkdf2_derive(kmc_data, KMC_HEADER_LEN,
                       zero_salt, 32,
                       candidates[count], 32);
        count++;
    }

    /* Candidate 6: PBKDF2(header, salt="", 1 iter) */
    if (count < max_cand) {
        pbkdf2_derive(kmc_data, KMC_HEADER_LEN,
                       (const uint8_t *)"", 0,
                       candidates[count], 32);
        count++;
    }

    /* Candidate 7-N: Try 96-byte flash head regions within KMC store */
    for (size_t off = 0; off + KMC_KEY_REGION_LEN <= kmc_len && count < max_cand;
         off += KMC_HEADER_LEN)
    {
        const uint8_t *head = kmc_data + off;
        /* DM_ReadKeyFromFlashHead pattern: salt = head[0:32], material = head[32:64] */
        pbkdf2_derive(head + KEYFILE_MATERIAL_OFFSET, KEYFILE_MATERIAL_LEN,
                       head, KEYFILE_MATERIAL_OFFSET,
                       candidates[count], 32);
        count++;
    }
#endif
    return count;
}

/* ── AEST decrypt attempt ─────────────────────────────────────────────── */
static int try_aest_decrypt(const uint8_t *data, size_t len,
                             const uint8_t *key,
                             uint8_t **out, size_t *out_len)
{
#if !defined(HAVE_MBEDTLS)
    return -1;
#else
    /* AEST header: version(4) + flags(4) + IV(16) + ciphertext + CRC(4) */
    if (len < 24 + 16 + 4)
        return -1;

    uint32_t version, flags;
    memcpy(&version, data, 4);
    memcpy(&flags, data + 4, 4);

    if (version != 0x04 || flags != 0x01)
        return -1;

    const uint8_t *iv = data + 8;
    size_t ct_len = len - 24 - 4;
    const uint8_t *ct = data + 24;

    /* Must be aligned to 16 */
    if (ct_len % 16 != 0 || ct_len == 0)
        return -1;

    uint8_t *plain = malloc(ct_len);
    if (!plain)
        return -1;

    if (aes_cbc_decrypt(ct, ct_len, key, 32, iv, plain) != 0) {
        free(plain);
        return -1;
    }

    /* Check PKCS#7 padding */
    uint8_t pad = plain[ct_len - 1];
    size_t plain_len = ct_len;
    if (pad >= 1 && pad <= 16) {
        int valid = 1;
        for (int i = 0; i < pad; i++) {
            if (plain[ct_len - 1 - i] != pad)
                valid = 0;
        }
        if (valid)
            plain_len = ct_len - pad;
    }

    /* Check if result looks like XML */
    if (plain_len > 0 && (plain[0] == '<' || (plain[0] == 0xEF && plain_len > 3 && plain[3] == '<'))) {
        *out = plain;
        *out_len = plain_len;
        return 0;
    }

    free(plain);
    return -1;
#endif
}

/* ── File I/O ─────────────────────────────────────────────────────────── */
static int read_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    *out = malloc((size_t)sz);
    if (!*out) { fclose(f); return -1; }
    *out_len = fread(*out, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);
    return 0;
}

/* ── Main ─────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    printf("kmc_decrypt – KMC store key derivation + AEST decryption\n\n");

    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s <kmc_store> <encrypted.xml> [output.xml]\n", argv[0]);
        printf("  %s --scan <kmc_store>   (dump candidate keys)\n", argv[0]);
        return 1;
    }

    /* --scan mode: dump candidate keys */
    if (strcmp(argv[1], "--scan") == 0) {
        uint8_t *kmc_data = NULL;
        size_t   kmc_len = 0;
        if (read_file(argv[2], &kmc_data, &kmc_len) != 0) {
            fprintf(stderr, "Cannot read %s\n", argv[2]);
            return 1;
        }

        printf("KMC store: %s (%zu bytes)\n", argv[2], kmc_len);
        printf("Header (first 32 bytes):\n  ");
        for (int i = 0; i < 32 && i < (int)kmc_len; i++)
            printf("%02x", kmc_data[i]);
        printf("\n");

        uint8_t candidates[MAX_CANDIDATES][32];
        int n = derive_kmc_candidates(kmc_data, kmc_len, candidates, MAX_CANDIDATES);
        printf("\nDerived %d candidate keys:\n", n);
        for (int i = 0; i < n; i++) {
            printf("  [%2d] ", i);
            for (int j = 0; j < 32; j++)
                printf("%02x", candidates[i][j]);
            printf("\n");
        }

        free(kmc_data);
        return 0;
    }

    /* Normal mode: try decrypt */
    const char *kmc_path = argv[1];
    const char *enc_path = argv[2];
    const char *out_path = argc > 3 ? argv[3] : NULL;

    uint8_t *kmc_data = NULL, *enc_data = NULL;
    size_t   kmc_len = 0, enc_len = 0;

    if (read_file(kmc_path, &kmc_data, &kmc_len) != 0) {
        fprintf(stderr, "Cannot read KMC store: %s\n", kmc_path);
        return 1;
    }
    if (read_file(enc_path, &enc_data, &enc_len) != 0) {
        fprintf(stderr, "Cannot read encrypted file: %s\n", enc_path);
        free(kmc_data);
        return 1;
    }

    printf("KMC store:  %s (%zu bytes)\n", kmc_path, kmc_len);
    printf("Encrypted:  %s (%zu bytes)\n", enc_path, enc_len);

    /* Derive candidate keys */
    uint8_t candidates[MAX_CANDIDATES][32];
    int n = derive_kmc_candidates(kmc_data, kmc_len, candidates, MAX_CANDIDATES);
    printf("Derived %d candidate keys\n\n", n);

    /* Try each candidate */
    int success = 0;
    for (int i = 0; i < n; i++) {
        uint8_t *plain = NULL;
        size_t   plain_len = 0;

        if (try_aest_decrypt(enc_data, enc_len, candidates[i],
                              &plain, &plain_len) == 0) {
            printf("✓ Decrypted with key #%d: ", i);
            for (int j = 0; j < 32; j++)
                printf("%02x", candidates[i][j]);
            printf("\n");
            printf("  Plaintext: %zu bytes\n", plain_len);
            printf("  Preview:   %.200s\n", (const char *)plain);

            if (out_path) {
                write_file(out_path, plain, plain_len);
                printf("  Saved to:  %s\n", out_path);
            }

            free(plain);
            success = 1;
            break;
        }
    }

    if (!success) {
        printf("✗ Could not decrypt with any KMC-derived key.\n");
        printf("  The hw_ctree.xml is protected by the device eFuse OTP.\n");
        printf("  The KMC store alone is not sufficient without the eFuse key\n");
        printf("  to decrypt the 96-byte flash head via DM_LdspDecryptData().\n");
    }

    free(kmc_data);
    free(enc_data);
    return success ? 0 : 1;
}
