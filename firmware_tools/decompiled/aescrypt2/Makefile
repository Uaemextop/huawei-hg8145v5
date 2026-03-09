# Build decompiled aescrypt2 + kmc_decrypt (host x86-64, for analysis/testing)
# Requires: libmbedtls-dev (apt install libmbedtls-dev)
#
# For ARM target (on-device): use cmake from HuaweiFirmwareTool/decompiled/
# For QEMU chroot: use the ARM binary from firmware rootfs /bin/aescrypt2

CC ?= gcc
CFLAGS = -O2 -Wall -DHAVE_MBEDTLS
LDFLAGS = -lmbedcrypto

COMMON_OBJS = hw_ssp_aescrypt.o hw_os_stubs.o

all: aescrypt2 kmc_decrypt

aescrypt2: aescrypt2.o $(COMMON_OBJS)
$(CC) -o $@ $^ $(LDFLAGS)

kmc_decrypt: kmc_decrypt.o $(COMMON_OBJS)
$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
$(CC) $(CFLAGS) -c $< -o $@

clean:
rm -f *.o aescrypt2 kmc_decrypt

test: aescrypt2
@echo '<?xml version="1.0"?><test/>' > /tmp/_aescrypt2_test.xml
./aescrypt2 0 /tmp/_aescrypt2_test.xml /tmp/_aescrypt2_test.enc
./aescrypt2 1 /tmp/_aescrypt2_test.enc /tmp/_aescrypt2_test.dec
@diff /tmp/_aescrypt2_test.xml /tmp/_aescrypt2_test.dec && echo "PASS: roundtrip OK"
@rm -f /tmp/_aescrypt2_test.*

.PHONY: all clean test
