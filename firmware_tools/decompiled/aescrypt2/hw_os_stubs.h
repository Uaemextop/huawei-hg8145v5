/*
 * hw_os_stubs.h  –  Host-build stubs for Huawei OS and safe-string helpers.
 */
#ifndef HW_OS_STUBS_H
#define HW_OS_STUBS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Huawei OS helpers */
int   HW_OS_Printf(const char *fmt, ...);
void  HW_PROC_DBG_LastWord(int line, const char *file,
                            const char *msg, int a, int b, int c);
int   HW_OS_StrToUInt32(const char *str, uint32_t *val_out);
void *HW_OS_MemMallocSet(size_t size);
void  HW_OS_MemFreeD(void *ptr);
int   MemGetRootKeyCfg(void *buf);
void *MemGetMkInfoByContent(void);
void  MSG_GetShmData(void *dst, int zero, size_t len);

/* Safe-string stubs (C11 Annex K) */
#if !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)
int strcpy_s(char *dst, size_t dst_sz, const char *src);
int strncpy_s(char *dst, size_t dst_sz, const char *src, size_t count);
int memset_s(void *s, size_t smax, int c, size_t n);
int memcpy_s(void *dst, size_t dstsz, const void *src, size_t n);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HW_OS_STUBS_H */
