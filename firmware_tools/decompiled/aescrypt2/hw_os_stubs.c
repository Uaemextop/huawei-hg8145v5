/*
 * hw_os_stubs.c  –  Host-build stubs for Huawei OS helpers
 *
 * On the target device these symbols are provided by libhw_ssp_basic.so.
 * For host builds (analysis / unit-testing) this file provides minimal
 * compatible implementations so the code links without the Huawei runtime.
 *
 * Do NOT ship this file to the device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* ── HW_OS_Printf ───────────────────────────────────────────────────────── */
int HW_OS_Printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    return n;
}

/* ── HW_PROC_DBG_LastWord ───────────────────────────────────────────────── */
void HW_PROC_DBG_LastWord(int line, const char *file,
                           const char *msg, int a, int b, int c)
{
    fprintf(stderr, "[DBG] %s:%d %s (0x%x 0x%x 0x%x)\n",
            file ? file : "?", line,
            msg  ? msg  : "", a, b, c);
}

/* ── HW_OS_StrToUInt32 ──────────────────────────────────────────────────── */
int HW_OS_StrToUInt32(const char *str, uint32_t *val_out)
{
    if (!str || !val_out)
        return -1;
    char *end;
    unsigned long v = strtoul(str, &end, 10);
    if (end == str || *end != '\0')
        return -1;
    *val_out = (uint32_t)v;
    return 0;
}

/* ── HW_OS_MemMallocSet ─────────────────────────────────────────────────── */
void *HW_OS_MemMallocSet(size_t size)
{
    void *p = calloc(1, size);
    return p;
}

/* ── HW_OS_MemFreeD ─────────────────────────────────────────────────────── */
void HW_OS_MemFreeD(void *ptr)
{
    free(ptr);
}

/* ── C11 Annex K safe-string stubs (not in all libc implementations) ──────── */
#if !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
int strcpy_s(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return -1;
    if (!src) { dst[0] = '\0'; return -1; }
    size_t n = strlen(src);
    if (n >= dst_sz) { dst[0] = '\0'; return -1; }
    memcpy(dst, src, n + 1);
    return 0;
}
int strncpy_s(char *dst, size_t dst_sz, const char *src, size_t count)
{
    if (!dst || dst_sz == 0) return -1;
    if (!src) { dst[0] = '\0'; return -1; }
    size_t n = (count < dst_sz) ? count : dst_sz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}
int memset_s(void *s, size_t smax, int c, size_t n)
{
    if (!s || n > smax) return -1;
    memset(s, c, n);
    return 0;
}
int memcpy_s(void *dst, size_t dstsz, const void *src, size_t n)
{
    if (!dst || !src || n > dstsz) return -1;
    memcpy(dst, src, n);
    return 0;
}
#endif /* !__STDC_LIB_EXT1__ */

/* ── MemGetRootKeyCfg (stub – returns 1 = key not available) ────────────── */
int MemGetRootKeyCfg(void *buf)
{
    (void)buf;
    /* On device: reads device-bound key from flash keyfile partition.
     * Off-device: not available – callers must handle non-zero return. */
    fprintf(stderr, "[STUB] MemGetRootKeyCfg: device key not available on host\n");
    return 1; /* error */
}

/* ── MemGetMkInfoByContent (stub) ───────────────────────────────────────── */
void *MemGetMkInfoByContent(void)
{
    return NULL;
}

/* ── MSG_GetShmData (stub – memset to zero) ─────────────────────────────── */
void MSG_GetShmData(void *dst, int zero, size_t len)
{
    (void)zero;
    if (dst)
        memset(dst, 0, len);
}

/* ── polarssl wrappers (forward to mbedTLS when available) ──────────────── */
#if defined(HAVE_MBEDTLS)
#include <mbedtls/aes.h>

typedef struct { mbedtls_aes_context ctx; } polarssl_aes_context;

void polarssl_aes_init(polarssl_aes_context *ctx)
{
    mbedtls_aes_init(&ctx->ctx);
}
int polarssl_aes_setkey_enc(polarssl_aes_context *ctx,
                             const unsigned char *key, unsigned int keybits)
{
    return mbedtls_aes_setkey_enc(&ctx->ctx, key, keybits);
}
int polarssl_aes_setkey_dec(polarssl_aes_context *ctx,
                             const unsigned char *key, unsigned int keybits)
{
    return mbedtls_aes_setkey_dec(&ctx->ctx, key, keybits);
}
int polarssl_aes_crypt_cbc(polarssl_aes_context *ctx, int mode,
                            size_t length, unsigned char *iv,
                            const unsigned char *input, unsigned char *output)
{
    return mbedtls_aes_crypt_cbc(&ctx->ctx, mode, length, iv, input, output);
}
#endif /* HAVE_MBEDTLS */
