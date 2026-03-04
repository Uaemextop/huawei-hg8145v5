#!/bin/bash
# qemu_decrypt.sh - Decrypt Huawei hw_*.xml using the real ARM aescrypt2
#                   binary via QEMU user-mode chroot.
#
# Prerequisites:
#   sudo apt install qemu-user-static squashfs-tools
#
# Usage:
#   ./qemu_decrypt.sh <firmware.bin> [output_dir]
#
# This script:
#   1. Parses the HWNP firmware and extracts the SquashFS rootfs
#   2. Sets up a QEMU ARM chroot in the extracted rootfs
#   3. Runs /bin/aescrypt2 (the real ARM binary) to decrypt hw_*.xml
#   4. Copies decrypted files to output_dir
#
# Note: The hw_ctree.xml and hw_default_ctree.xml are encrypted with
# device-bound eFuse keys. The aescrypt2 binary uses MemGetRootKeyCfg()
# which requires the device's shared memory segment. Without the actual
# device hardware, these files cannot be decrypted.
# However, hw_diag_cli.xml and hw_shell_cli.xml may use a different
# (non-eFuse) key path and could potentially be decrypted.

set -e

FIRMWARE="${1:?Usage: $0 <firmware.bin> [output_dir]}"
OUTDIR="${2:-./decrypted_configs}"
WORKDIR=$(mktemp -d)
ROOTFS="$WORKDIR/rootfs"

cleanup() { sudo rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "[1] Extracting SquashFS from firmware: $FIRMWARE"
python3 -c "
import struct, sys
data = open('$FIRMWARE', 'rb').read()
# Find squashfs magic 'hsqs'
off = data.find(b'hsqs')
if off < 0:
    # Try inside HWNP items
    magic = b'HWNP'
    if data[:4] == magic:
        # Scan for hsqs in all items
        off = data.find(b'hsqs', 4)
if off < 0:
    print('No SquashFS found'); sys.exit(1)
with open('$WORKDIR/rootfs.sqfs', 'wb') as f:
    f.write(data[off:])
print(f'SquashFS at offset {off:#x}, {len(data)-off} bytes')
"

echo "[2] Extracting rootfs"
sudo unsquashfs -d "$ROOTFS" "$WORKDIR/rootfs.sqfs" > /dev/null 2>&1

echo "[3] Setting up QEMU ARM chroot"
sudo cp /usr/bin/qemu-arm-static "$ROOTFS/usr/bin/" 2>/dev/null || \
    sudo cp "$(which qemu-arm-static)" "$ROOTFS/usr/bin/"
sudo chmod -R a+rX "$ROOTFS/bin/" "$ROOTFS/lib/" "$ROOTFS/usr/"
sudo mkdir -p "$ROOTFS/tmp"

echo "[4] Finding encrypted hw_*.xml files"
mkdir -p "$OUTDIR"

find "$ROOTFS" -name 'hw_*.xml' -type f | while read f; do
    rel=$(echo "$f" | sed "s|$ROOTFS/||")
    name=$(basename "$f")
    
    # Check if encrypted (first byte != '<')
    first=$(head -c1 "$f" | xxd -p)
    if [ "$first" = "3c" ]; then
        # Plaintext - copy directly
        cp "$f" "$OUTDIR/$name" 2>/dev/null || true
        continue
    fi
    
    # Try decrypt
    sudo cp "$f" "$ROOTFS/tmp/input.xml"
    if sudo chroot "$ROOTFS" /usr/bin/qemu-arm-static /bin/aescrypt2 1 \
        /tmp/input.xml /tmp/output.xml 2>/dev/null; then
        if [ -f "$ROOTFS/tmp/output.xml" ]; then
            sudo cp "$ROOTFS/tmp/output.xml" "$OUTDIR/${name%.xml}_decrypted.xml"
            echo "  ✓ $rel → decrypted"
        fi
    else
        echo "  ✗ $rel → needs eFuse key"
    fi
    sudo rm -f "$ROOTFS/tmp/input.xml" "$ROOTFS/tmp/output.xml"
done

echo ""
echo "[5] Results in $OUTDIR/"
ls -la "$OUTDIR/"
