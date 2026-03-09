#!/usr/bin/env python3
"""
Firmware Extractor and Analyzer

Analyzes firmware binaries to extract:
- PEM/DER certificates and keys
- Credentials (usernames/passwords)
- Private keys (RSA, DSA, EC)
- Encrypted file analysis
- Capstone disassembly for embedded key material
"""

import os
import re
import sys
import json
import struct
import hashlib
import binascii
import argparse
import datetime
from pathlib import Path

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    from Crypto.PublicKey import RSA, DSA, ECC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ─── PEM / Key Patterns ─────────────────────────────────────────────────────
PEM_PATTERNS = [
    (b'-----BEGIN CERTIFICATE-----', b'-----END CERTIFICATE-----', 'certificate'),
    (b'-----BEGIN RSA PRIVATE KEY-----', b'-----END RSA PRIVATE KEY-----', 'rsa_private_key'),
    (b'-----BEGIN DSA PRIVATE KEY-----', b'-----END DSA PRIVATE KEY-----', 'dsa_private_key'),
    (b'-----BEGIN EC PRIVATE KEY-----', b'-----END EC PRIVATE KEY-----', 'ec_private_key'),
    (b'-----BEGIN PRIVATE KEY-----', b'-----END PRIVATE KEY-----', 'private_key'),
    (b'-----BEGIN ENCRYPTED PRIVATE KEY-----', b'-----END ENCRYPTED PRIVATE KEY-----', 'encrypted_private_key'),
    (b'-----BEGIN PUBLIC KEY-----', b'-----END PUBLIC KEY-----', 'public_key'),
    (b'-----BEGIN RSA PUBLIC KEY-----', b'-----END RSA PUBLIC KEY-----', 'rsa_public_key'),
    (b'-----BEGIN X509 CRL-----', b'-----END X509 CRL-----', 'x509_crl'),
    (b'-----BEGIN CERTIFICATE REQUEST-----', b'-----END CERTIFICATE REQUEST-----', 'cert_request'),
    (b'-----BEGIN DH PARAMETERS-----', b'-----END DH PARAMETERS-----', 'dh_parameters'),
]

# DER magic bytes for certificates and keys
DER_PATTERNS = [
    (b'\x30\x82', 'der_sequence'),  # ASN.1 SEQUENCE (long form)
    (b'\x30\x81', 'der_sequence_short'),  # ASN.1 SEQUENCE (short form)
]

# Known Huawei firmware encryption key
KNOWN_AES_KEY = b'Df7!ui%s9(lmV1L8'

# Credential patterns for config files
CREDENTIAL_PATTERNS = [
    # XML config patterns
    re.compile(rb'<UserName[^>]*>([^<]+)</UserName>', re.IGNORECASE),
    re.compile(rb'<Password[^>]*>([^<]+)</Password>', re.IGNORECASE),
    re.compile(rb'<username[^>]*>([^<]+)</username>', re.IGNORECASE),
    re.compile(rb'<password[^>]*>([^<]+)</password>', re.IGNORECASE),
    re.compile(rb'Username\s*=\s*"([^"]+)"', re.IGNORECASE),
    re.compile(rb'Password\s*=\s*"([^"]+)"', re.IGNORECASE),
    re.compile(rb'<ACSUrl[^>]*>([^<]+)</ACSUrl>', re.IGNORECASE),
    re.compile(rb'<ConnectionRequestUsername[^>]*>([^<]+)</ConnectionRequestUsername>', re.IGNORECASE),
    re.compile(rb'<ConnectionRequestPassword[^>]*>([^<]+)</ConnectionRequestPassword>', re.IGNORECASE),
    re.compile(rb'ManagementServer\.Username\s*=\s*([^\s<]+)', re.IGNORECASE),
    re.compile(rb'ManagementServer\.Password\s*=\s*([^\s<]+)', re.IGNORECASE),
    # Generic patterns
    re.compile(rb'(?:admin|root|user|login)[\s:=]+([^\s<"\']{3,30})', re.IGNORECASE),
    re.compile(rb'(?:pass|pwd|passwd|password|secret|key)[\s:=]+([^\s<"\']{3,60})', re.IGNORECASE),
    # WiFi passwords
    re.compile(rb'<(?:Pre)?SharedKey[^>]*>([^<]+)</(?:Pre)?SharedKey>', re.IGNORECASE),
    re.compile(rb'<KeyPassphrase[^>]*>([^<]+)</KeyPassphrase>', re.IGNORECASE),
    re.compile(rb'WPAKey\s*=\s*"([^"]+)"', re.IGNORECASE),
    # TR-069 ACS credentials
    re.compile(rb'<X_HW_ACSConnUserName[^>]*>([^<]+)</X_HW_ACSConnUserName>', re.IGNORECASE),
    re.compile(rb'<X_HW_ACSConnPassword[^>]*>([^<]+)</X_HW_ACSConnPassword>', re.IGNORECASE),
]

# Patterns for finding key material in binary data
BINARY_KEY_PATTERNS = [
    # RSA key markers
    (rb'\x30\x82[\x00-\xff]{2}\x02\x01\x00\x02\x82', 'RSA Private Key (PKCS#1)'),
    (rb'\x30\x82[\x00-\xff]{2}\x02\x01\x00\x30\x0d\x06\x09', 'Private Key (PKCS#8)'),
    # SSH key markers
    (rb'ssh-rsa\s+[A-Za-z0-9+/=]+', 'SSH RSA Public Key'),
    (rb'ssh-dss\s+[A-Za-z0-9+/=]+', 'SSH DSA Public Key'),
    (rb'ssh-ed25519\s+[A-Za-z0-9+/=]+', 'SSH Ed25519 Public Key'),
    # Dropbear key format
    (rb'\x00\x00\x00\x07ssh-rsa', 'Dropbear RSA Key'),
    (rb'\x00\x00\x00\x07ssh-dss', 'Dropbear DSA Key'),
    # AES key-like patterns (16/24/32 byte sequences preceded by key-related strings)
    (rb'(?:aes|AES|encrypt|ENCRYPT|key|KEY|secret|SECRET).{0,20}([\x20-\x7e]{16,32})', 'Potential AES Key String'),
]

# Firmware header signatures
FIRMWARE_SIGNATURES = {
    b'HWNP': 'Huawei HWNP firmware',
    b'\x27\x05\x19\x56': 'U-Boot uImage',
    b'hsqs': 'SquashFS (little-endian)',
    b'sqsh': 'SquashFS (big-endian)',
    b'\x1f\x8b': 'Gzip compressed',
    b'\x42\x5a\x68': 'Bzip2 compressed',
    b'\xfd\x37\x7a\x58\x5a\x00': 'XZ compressed',
    b'\x89PNG': 'PNG image',
    b'PK\x03\x04': 'ZIP archive',
    b'\x7fELF': 'ELF binary',
    b'MZ': 'PE executable',
}


class FirmwareExtractor:
    """Extract keys, certificates, and credentials from firmware files."""

    def __init__(self, output_dir='firmware_analysis'):
        self.output_dir = Path(output_dir)
        self.keys_dir = self.output_dir / 'extracted_keys'
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.findings = {
            'pem_certificates': [],
            'pem_keys': [],
            'der_certificates': [],
            'credentials': [],
            'binary_keys': [],
            'encrypted_files': [],
            'firmware_info': [],
            'capstone_findings': [],
        }

    def analyze_firmware_file(self, filepath):
        """Analyze a single firmware file."""
        filepath = Path(filepath)
        if not filepath.exists():
            return

        filesize = filepath.stat().st_size
        filename = filepath.name

        print(f"\n{'='*70}")
        print(f"Analyzing: {filename} ({filesize:,} bytes)")
        print(f"{'='*70}")

        with open(filepath, 'rb') as f:
            data = f.read()

        # Identify firmware type
        fw_type = self._identify_firmware(data, filename)
        self.findings['firmware_info'].append({
            'file': filename,
            'size': filesize,
            'type': fw_type,
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        })

        # Extract PEM certificates and keys
        self._extract_pem(data, filename)

        # Extract DER certificates
        self._extract_der(data, filename)

        # Extract credentials
        self._extract_credentials(data, filename)

        # Search for binary key material
        self._search_binary_keys(data, filename)

        # Analyze encrypted sections
        self._analyze_encrypted(data, filename)

        # Capstone disassembly analysis
        if HAS_CAPSTONE and filesize < 100 * 1024 * 1024:  # Skip >100MB
            self._capstone_analysis(data, filename)

    def _identify_firmware(self, data, filename):
        """Identify firmware type from magic bytes."""
        info = []
        for sig, name in FIRMWARE_SIGNATURES.items():
            if data[:len(sig)] == sig:
                info.append(f"Header: {name}")

            # Also search for embedded signatures
            offset = data.find(sig, 0, min(len(data), 1024 * 1024))
            if offset > 0:
                info.append(f"Embedded {name} at offset 0x{offset:x}")

        if not info:
            info.append(f"Unknown format (magic: {data[:4].hex()})")

        fw_type = '; '.join(info)
        print(f"  Type: {fw_type}")
        return fw_type

    def _extract_pem(self, data, filename):
        """Extract PEM-encoded certificates and keys."""
        for begin, end, pem_type in PEM_PATTERNS:
            start = 0
            count = 0
            while True:
                idx = data.find(begin, start)
                if idx == -1:
                    break

                end_idx = data.find(end, idx)
                if end_idx == -1:
                    break

                pem_data = data[idx:end_idx + len(end)]
                count += 1

                # Save the PEM data
                ext = '.pem' if 'certificate' in pem_type else '.key'
                if 'public' in pem_type:
                    ext = '.pub'
                safe_name = re.sub(r'[^\w.-]', '_', filename)
                out_name = f"{safe_name}_{pem_type}_{count}{ext}"
                out_path = self.keys_dir / out_name
                with open(out_path, 'wb') as f:
                    f.write(pem_data)

                # Parse certificate details if possible
                details = self._parse_pem_details(pem_data, pem_type)

                finding = {
                    'file': filename,
                    'type': pem_type,
                    'offset': idx,
                    'size': len(pem_data),
                    'saved_as': str(out_path),
                    'details': details,
                    'md5': hashlib.md5(pem_data).hexdigest(),
                }

                if 'key' in pem_type.lower():
                    self.findings['pem_keys'].append(finding)
                    print(f"  [KEY] Found {pem_type} at offset 0x{idx:x} ({len(pem_data)} bytes)")
                else:
                    self.findings['pem_certificates'].append(finding)
                    print(f"  [CERT] Found {pem_type} at offset 0x{idx:x} ({len(pem_data)} bytes)")

                if details:
                    for k, v in details.items():
                        print(f"         {k}: {v}")

                start = end_idx + len(end)

    def _parse_pem_details(self, pem_data, pem_type):
        """Parse PEM data to extract details."""
        details = {}

        if not HAS_CRYPTOGRAPHY:
            return details

        try:
            if pem_type == 'certificate':
                cert = x509.load_pem_x509_certificate(pem_data)
                details['subject'] = str(cert.subject)
                details['issuer'] = str(cert.issuer)
                details['not_before'] = str(cert.not_valid_before_utc)
                details['not_after'] = str(cert.not_valid_after_utc)
                details['serial'] = str(cert.serial_number)
                details['algorithm'] = cert.signature_algorithm_oid.dotted_string
            elif 'private_key' in pem_type or pem_type == 'private_key':
                if 'encrypted' not in pem_type:
                    try:
                        key = serialization.load_pem_private_key(pem_data, password=None)
                        details['key_size'] = getattr(key, 'key_size', 'unknown')
                        details['key_type'] = type(key).__name__
                    except Exception:
                        details['encrypted'] = True
                        details['note'] = 'Password-protected private key'
                else:
                    details['encrypted'] = True
            elif 'public_key' in pem_type:
                try:
                    key = serialization.load_pem_public_key(pem_data)
                    details['key_size'] = getattr(key, 'key_size', 'unknown')
                    details['key_type'] = type(key).__name__
                except Exception:
                    pass
        except Exception as e:
            details['parse_error'] = str(e)

        return details

    def _extract_der(self, data, filename):
        """Extract DER-encoded certificates from binary data."""
        # Look for ASN.1 SEQUENCE structures that could be certificates
        offset = 0
        count = 0
        while offset < len(data) - 4:
            if data[offset] == 0x30 and data[offset + 1] == 0x82:
                # Long form length: 2 bytes following
                length = struct.unpack('>H', data[offset + 2:offset + 4])[0]
                total_len = length + 4  # header + content

                if 100 < total_len < 10000 and offset + total_len <= len(data):
                    der_data = data[offset:offset + total_len]

                    # Verify it looks like a certificate or key
                    if self._is_valid_der(der_data):
                        count += 1
                        safe_name = re.sub(r'[^\w.-]', '_', filename)
                        out_name = f"{safe_name}_der_{count}.der"
                        out_path = self.keys_dir / out_name
                        with open(out_path, 'wb') as f:
                            f.write(der_data)

                        details = self._parse_der_details(der_data)
                        finding = {
                            'file': filename,
                            'offset': offset,
                            'size': total_len,
                            'saved_as': str(out_path),
                            'details': details,
                            'md5': hashlib.md5(der_data).hexdigest(),
                        }
                        self.findings['der_certificates'].append(finding)
                        print(f"  [DER] Found DER structure at offset 0x{offset:x} ({total_len} bytes)")
                        if details:
                            for k, v in details.items():
                                print(f"         {k}: {v}")

                        offset += total_len
                        continue

            offset += 1

    def _is_valid_der(self, der_data):
        """Check if DER data is a valid certificate or key."""
        if HAS_CRYPTOGRAPHY:
            try:
                x509.load_der_x509_certificate(der_data)
                return True
            except Exception:
                pass
            try:
                serialization.load_der_public_key(der_data)
                return True
            except Exception:
                pass
            try:
                serialization.load_der_private_key(der_data, password=None)
                return True
            except Exception:
                pass

        # Heuristic: check if it has certificate OIDs
        cert_oids = [
            b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01',  # RSA encryption
            b'\x06\x03\x55\x04\x03',  # Common Name
            b'\x06\x03\x55\x04\x06',  # Country
            b'\x06\x03\x55\x04\x0a',  # Organization
        ]
        matches = sum(1 for oid in cert_oids if oid in der_data)
        return matches >= 2

    def _parse_der_details(self, der_data):
        """Parse DER certificate details."""
        details = {}
        if not HAS_CRYPTOGRAPHY:
            return details

        try:
            cert = x509.load_der_x509_certificate(der_data)
            details['type'] = 'X.509 Certificate'
            details['subject'] = str(cert.subject)
            details['issuer'] = str(cert.issuer)
            details['not_before'] = str(cert.not_valid_before_utc)
            details['not_after'] = str(cert.not_valid_after_utc)
        except Exception:
            try:
                key = serialization.load_der_public_key(der_data)
                details['type'] = 'Public Key'
                details['key_size'] = getattr(key, 'key_size', 'unknown')
            except Exception:
                details['type'] = 'Unknown ASN.1 structure'

        return details

    def _extract_credentials(self, data, filename):
        """Extract credentials from config files and firmware."""
        for pattern in CREDENTIAL_PATTERNS:
            for match in pattern.finditer(data):
                value = match.group(1)
                try:
                    value_str = value.decode('utf-8', errors='replace')
                except Exception:
                    value_str = repr(value)

                # Filter out noise
                if len(value_str) < 2 or len(value_str) > 200:
                    continue
                if all(c == '0' or c == '\x00' for c in value_str):
                    continue
                if value_str.strip() in ('', '0', 'null', 'none', 'N/A'):
                    continue

                context_start = max(0, match.start() - 50)
                context_end = min(len(data), match.end() + 50)
                context = data[context_start:context_end]
                try:
                    context_str = context.decode('utf-8', errors='replace')
                except Exception:
                    context_str = repr(context)

                finding = {
                    'file': filename,
                    'pattern': pattern.pattern.decode('utf-8', errors='replace'),
                    'value': value_str,
                    'offset': match.start(),
                    'context': context_str.strip(),
                }

                # Avoid duplicates
                if not any(
                    f['file'] == filename and f['value'] == value_str and f['pattern'] == finding['pattern']
                    for f in self.findings['credentials']
                ):
                    self.findings['credentials'].append(finding)
                    print(f"  [CRED] Found credential: {value_str[:50]}...")

    def _search_binary_keys(self, data, filename):
        """Search for binary key material."""
        for pattern_bytes, key_type in BINARY_KEY_PATTERNS:
            pattern = re.compile(pattern_bytes, re.DOTALL)
            for match in pattern.finditer(data):
                offset = match.start()
                matched = match.group(0)

                # Save key material
                safe_name = re.sub(r'[^\w.-]', '_', filename)
                count = len(self.findings['binary_keys']) + 1
                out_name = f"{safe_name}_binkey_{count}.bin"
                out_path = self.keys_dir / out_name

                # Save a reasonable amount of context around the match
                ctx_start = max(0, offset - 16)
                ctx_end = min(len(data), match.end() + 256)
                with open(out_path, 'wb') as f:
                    f.write(data[ctx_start:ctx_end])

                finding = {
                    'file': filename,
                    'type': key_type,
                    'offset': offset,
                    'size': len(matched),
                    'saved_as': str(out_path),
                    'hex_preview': matched[:64].hex(),
                }
                self.findings['binary_keys'].append(finding)
                print(f"  [BINKEY] Found {key_type} at offset 0x{offset:x}")

        # Also search for the known AES key
        key_offset = data.find(KNOWN_AES_KEY)
        while key_offset != -1:
            finding = {
                'file': filename,
                'type': 'Known Huawei AES Key',
                'offset': key_offset,
                'key': KNOWN_AES_KEY.decode('ascii'),
                'note': 'Known firmware encryption key Df7!ui%s9(lmV1L8',
            }
            self.findings['binary_keys'].append(finding)
            print(f"  [BINKEY] Found known AES key at offset 0x{key_offset:x}")
            key_offset = data.find(KNOWN_AES_KEY, key_offset + 1)

    def _analyze_encrypted(self, data, filename):
        """Analyze potentially encrypted sections."""
        info = {
            'file': filename,
            'sections': [],
        }

        # Check for Huawei HWNP header
        if data[:4] == b'HWNP':
            hwnp_info = self._parse_hwnp(data, filename)
            info['sections'].append(hwnp_info)

        # Check for encrypted XML configs (Huawei uses AES-CBC)
        if b'<Encrypt>' in data or b'encrypt_spec_key' in data.lower():
            info['sections'].append({
                'type': 'encrypted_config',
                'note': 'Contains encrypted configuration data',
            })

        # Look for high entropy blocks (likely encrypted/compressed)
        block_size = 1024
        high_entropy_blocks = 0
        for i in range(0, min(len(data), 1024 * 1024), block_size):
            block = data[i:i + block_size]
            if len(block) == block_size:
                entropy = self._calc_entropy(block)
                if entropy > 7.5:
                    high_entropy_blocks += 1

        total_blocks = min(len(data), 1024 * 1024) // block_size
        if total_blocks > 0:
            encrypted_pct = (high_entropy_blocks / total_blocks) * 100
            info['encrypted_percentage'] = round(encrypted_pct, 1)
            if encrypted_pct > 50:
                info['sections'].append({
                    'type': 'high_entropy',
                    'note': f'{encrypted_pct:.1f}% of first 1MB has high entropy (encrypted/compressed)',
                })

        if info['sections']:
            self.findings['encrypted_files'].append(info)
            for section in info['sections']:
                print(f"  [ENC] {section.get('type', 'unknown')}: {section.get('note', '')}")

    def _parse_hwnp(self, data, filename):
        """Parse Huawei HWNP firmware header."""
        info = {'type': 'HWNP', 'fields': {}}
        try:
            if len(data) >= 64:
                # HWNP header structure
                info['fields']['magic'] = data[:4].decode('ascii')
                info['fields']['header_size'] = struct.unpack('<I', data[4:8])[0]
                # Version string often at offset 0x10-0x30
                ver_data = data[16:48]
                # Try to extract printable version string
                ver_str = ''
                for b in ver_data:
                    if 32 <= b < 127:
                        ver_str += chr(b)
                    elif ver_str:
                        break
                if ver_str:
                    info['fields']['version'] = ver_str
                info['note'] = f'Huawei HWNP firmware package'
        except Exception as e:
            info['parse_error'] = str(e)
        return info

    def _calc_entropy(self, data):
        """Calculate Shannon entropy of data block."""
        if not data:
            return 0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * (p and __import__('math').log2(p))
        return entropy

    def _capstone_analysis(self, data, filename):
        """Use Capstone to disassemble and find key-related code."""
        if not HAS_CAPSTONE:
            print("  [SKIP] Capstone not available")
            return

        # Check if it's an ELF or has ARM/MIPS code
        is_elf = data[:4] == b'\x7fELF'
        is_arm = False
        arch = None
        mode = None

        if is_elf and len(data) > 18:
            e_machine = struct.unpack('<H', data[18:20])[0]
            if e_machine == 40:  # ARM
                is_arm = True
                arch = capstone.CS_ARCH_ARM
                mode = capstone.CS_MODE_ARM
            elif e_machine == 8:  # MIPS
                arch = capstone.CS_ARCH_MIPS
                mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN
            elif e_machine == 3:  # x86
                arch = capstone.CS_ARCH_X86
                mode = capstone.CS_MODE_32
            elif e_machine == 62:  # x86_64
                arch = capstone.CS_ARCH_X86
                mode = capstone.CS_MODE_64
        else:
            # Try ARM LE as default for firmware
            arch = capstone.CS_ARCH_ARM
            mode = capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN

        if arch is None:
            return

        # Look for key-related strings first
        key_strings = [
            b'private', b'PRIVATE', b'RSA', b'AES', b'encrypt',
            b'ENCRYPT', b'decrypt', b'DECRYPT', b'key', b'KEY',
            b'certificate', b'CERTIFICATE', b'passwd', b'password',
            b'secret', b'SECRET', b'prvt', b'PRVT',
        ]

        key_offsets = set()
        for ks in key_strings:
            idx = 0
            while idx < len(data):
                pos = data.find(ks, idx)
                if pos == -1:
                    break
                key_offsets.add(pos)
                idx = pos + 1

        if not key_offsets:
            return

        print(f"  [CAPSTONE] Found {len(key_offsets)} key-related string references")

        # Disassemble around key-related offsets
        md = capstone.Cs(arch, mode)
        md.detail = False
        findings_count = 0
        max_findings = 50  # Limit

        for offset in sorted(key_offsets):
            if findings_count >= max_findings:
                break

            # Get context around the reference
            ctx_start = max(0, offset - 64)
            ctx_end = min(len(data), offset + 128)
            context = data[ctx_start:ctx_end]

            # Try to get the referenced string
            ref_str = b''
            for b in data[offset:offset + 64]:
                if 32 <= b < 127:
                    ref_str += bytes([b])
                elif ref_str:
                    break

            if len(ref_str) < 4:
                continue

            try:
                instructions = list(md.disasm(context, ctx_start))
                if instructions:
                    finding = {
                        'file': filename,
                        'offset': offset,
                        'string': ref_str.decode('ascii', errors='replace'),
                        'instruction_count': len(instructions),
                        'first_instructions': [],
                    }

                    for insn in instructions[:5]:
                        finding['first_instructions'].append(
                            f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}"
                        )

                    self.findings['capstone_findings'].append(finding)
                    findings_count += 1
            except Exception:
                pass

        if findings_count > 0:
            print(f"  [CAPSTONE] Analyzed {findings_count} key-related code sections")

    def analyze_directory(self, directory):
        """Analyze all firmware files in a directory."""
        directory = Path(directory)
        if not directory.exists():
            print(f"Directory not found: {directory}")
            return

        firmware_files = []
        for ext in ['*.bin', '*.img', '*.fw', '*.rom', '*.dat', '*.enc']:
            firmware_files.extend(directory.glob(ext))

        # Also include files without extension that might be firmware
        for f in directory.iterdir():
            if f.is_file() and f.suffix == '' and f.name not in ('.', '..'):
                firmware_files.append(f)

        # Also include XML config files for credential extraction
        for ext in ['*.xml', '*.cfg', '*.conf', '*.ini', '*.key', '*.pem', '*.crt', '*.der']:
            firmware_files.extend(directory.glob(ext))

        firmware_files = sorted(set(firmware_files))
        print(f"\nFound {len(firmware_files)} files to analyze")

        for fw_file in firmware_files:
            try:
                self.analyze_firmware_file(fw_file)
            except Exception as e:
                print(f"  [ERROR] Failed to analyze {fw_file}: {e}")

    def generate_reports(self):
        """Generate analysis reports."""
        self._generate_credentials_report()
        self._generate_private_keys_report()
        self._generate_full_report()
        self._save_json_results()

    def _generate_credentials_report(self):
        """Generate credentials report."""
        report = []
        report.append("# Firmware Credentials Report")
        report.append(f"\nGenerated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        report.append(f"\nTotal credentials found: {len(self.findings['credentials'])}")
        report.append("")

        # Group by file
        by_file = {}
        for cred in self.findings['credentials']:
            fname = cred['file']
            if fname not in by_file:
                by_file[fname] = []
            by_file[fname].append(cred)

        for fname, creds in sorted(by_file.items()):
            report.append(f"\n## {fname}")
            report.append("")
            report.append("| Pattern | Value | Offset |")
            report.append("|---------|-------|--------|")
            for cred in creds:
                pattern_short = cred['pattern'][:40].replace('|', '\\|')
                value = cred['value'][:60].replace('|', '\\|')
                report.append(f"| `{pattern_short}` | `{value}` | 0x{cred['offset']:x} |")
            report.append("")

        report_path = self.output_dir / 'CREDENTIALS.md'
        with open(report_path, 'w') as f:
            f.write('\n'.join(report))
        print(f"\nCredentials report saved to: {report_path}")

    def _generate_private_keys_report(self):
        """Generate private keys report."""
        report = []
        report.append("# Private Keys and Certificates Report")
        report.append(f"\nGenerated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        report.append("")

        # PEM Keys
        report.append("## PEM Private Keys")
        report.append(f"\nTotal found: {len(self.findings['pem_keys'])}")
        report.append("")
        for key in self.findings['pem_keys']:
            report.append(f"### {key['file']} - {key['type']}")
            report.append(f"- **Offset**: 0x{key['offset']:x}")
            report.append(f"- **Size**: {key['size']} bytes")
            report.append(f"- **MD5**: {key['md5']}")
            report.append(f"- **Saved as**: `{key['saved_as']}`")
            if key.get('details'):
                for k, v in key['details'].items():
                    report.append(f"- **{k}**: {v}")
            report.append("")

        # PEM Certificates
        report.append("## PEM Certificates")
        report.append(f"\nTotal found: {len(self.findings['pem_certificates'])}")
        report.append("")
        for cert in self.findings['pem_certificates']:
            report.append(f"### {cert['file']} - {cert['type']}")
            report.append(f"- **Offset**: 0x{cert['offset']:x}")
            report.append(f"- **Size**: {cert['size']} bytes")
            report.append(f"- **MD5**: {cert['md5']}")
            report.append(f"- **Saved as**: `{cert['saved_as']}`")
            if cert.get('details'):
                for k, v in cert['details'].items():
                    report.append(f"- **{k}**: {v}")
            report.append("")

        # DER Certificates
        report.append("## DER Certificates")
        report.append(f"\nTotal found: {len(self.findings['der_certificates'])}")
        report.append("")
        for cert in self.findings['der_certificates']:
            report.append(f"### {cert['file']}")
            report.append(f"- **Offset**: 0x{cert['offset']:x}")
            report.append(f"- **Size**: {cert['size']} bytes")
            report.append(f"- **MD5**: {cert['md5']}")
            report.append(f"- **Saved as**: `{cert['saved_as']}`")
            if cert.get('details'):
                for k, v in cert['details'].items():
                    report.append(f"- **{k}**: {v}")
            report.append("")

        # Binary Keys
        report.append("## Binary Key Material")
        report.append(f"\nTotal found: {len(self.findings['binary_keys'])}")
        report.append("")
        for key in self.findings['binary_keys']:
            report.append(f"### {key['file']} - {key['type']}")
            report.append(f"- **Offset**: 0x{key['offset']:x}")
            if key.get('key'):
                report.append(f"- **Key**: `{key['key']}`")
            if key.get('hex_preview'):
                report.append(f"- **Hex preview**: `{key['hex_preview'][:80]}`")
            if key.get('saved_as'):
                report.append(f"- **Saved as**: `{key['saved_as']}`")
            if key.get('note'):
                report.append(f"- **Note**: {key['note']}")
            report.append("")

        # Capstone findings
        if self.findings['capstone_findings']:
            report.append("## Capstone Disassembly Findings")
            report.append(f"\nTotal key-related code sections: {len(self.findings['capstone_findings'])}")
            report.append("")
            for finding in self.findings['capstone_findings'][:100]:
                report.append(f"### {finding['file']} @ 0x{finding['offset']:x}")
                report.append(f"- **String reference**: `{finding['string']}`")
                report.append(f"- **Instructions found**: {finding['instruction_count']}")
                if finding.get('first_instructions'):
                    report.append("- **Disassembly**:")
                    report.append("```asm")
                    for insn in finding['first_instructions']:
                        report.append(f"  {insn}")
                    report.append("```")
                report.append("")

        report_path = self.output_dir / 'PRIVATE_KEYS.md'
        with open(report_path, 'w') as f:
            f.write('\n'.join(report))
        print(f"\nPrivate keys report saved to: {report_path}")

    def _generate_full_report(self):
        """Generate comprehensive analysis report."""
        report = []
        report.append("# Firmware Analysis Report")
        report.append(f"\nGenerated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        report.append(f"\nSource: realfirmware-net repository (branch: copilot/extract-and-organize-compressed-files)")
        report.append("")

        # Summary
        report.append("## Summary")
        report.append("")
        report.append(f"| Category | Count |")
        report.append(f"|----------|-------|")
        report.append(f"| Firmware files analyzed | {len(self.findings['firmware_info'])} |")
        report.append(f"| PEM Certificates | {len(self.findings['pem_certificates'])} |")
        report.append(f"| PEM Keys | {len(self.findings['pem_keys'])} |")
        report.append(f"| DER Certificates | {len(self.findings['der_certificates'])} |")
        report.append(f"| Credentials | {len(self.findings['credentials'])} |")
        report.append(f"| Binary Key Material | {len(self.findings['binary_keys'])} |")
        report.append(f"| Encrypted Files | {len(self.findings['encrypted_files'])} |")
        report.append(f"| Capstone Findings | {len(self.findings['capstone_findings'])} |")
        report.append("")

        # Firmware inventory
        report.append("## Firmware Inventory")
        report.append("")
        report.append("| File | Size | Type | MD5 |")
        report.append("|------|------|------|-----|")
        for fw in self.findings['firmware_info']:
            size_str = self._format_size(fw['size'])
            type_short = fw['type'][:60]
            report.append(f"| {fw['file']} | {size_str} | {type_short} | `{fw['md5'][:12]}...` |")
        report.append("")

        # Encrypted files analysis
        if self.findings['encrypted_files']:
            report.append("## Encrypted File Analysis")
            report.append("")
            for enc in self.findings['encrypted_files']:
                report.append(f"### {enc['file']}")
                if 'encrypted_percentage' in enc:
                    report.append(f"- High-entropy data: {enc['encrypted_percentage']}%")
                for section in enc.get('sections', []):
                    report.append(f"- **{section.get('type', 'unknown')}**: {section.get('note', '')}")
                    if 'fields' in section:
                        for k, v in section['fields'].items():
                            report.append(f"  - {k}: {v}")
                report.append("")

        # Known keys summary
        report.append("## Known Encryption Keys")
        report.append("")
        report.append("### AES Key (Common across Huawei ONT firmware)")
        report.append(f"- **Key**: `{KNOWN_AES_KEY.decode('ascii')}`")
        report.append("- **Algorithm**: AES-256-CBC")
        report.append("- **Usage**: Firmware configuration encryption")
        report.append("- **Found in**: Multiple Huawei firmware binaries")
        report.append("")

        report_path = self.output_dir / 'FIRMWARE_ANALYSIS_REPORT.md'
        with open(report_path, 'w') as f:
            f.write('\n'.join(report))
        print(f"\nFull report saved to: {report_path}")

    def _save_json_results(self):
        """Save raw findings as JSON."""
        json_path = self.output_dir / 'findings.json'
        with open(json_path, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)
        print(f"JSON results saved to: {json_path}")

    @staticmethod
    def _format_size(size):
        """Format file size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


def main():
    parser = argparse.ArgumentParser(description='Firmware Extractor and Analyzer')
    parser.add_argument('input', nargs='?', default='firmware_bins',
                        help='Input directory or file to analyze')
    parser.add_argument('--output', '-o', default='firmware_analysis',
                        help='Output directory for results')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON only')
    args = parser.parse_args()

    extractor = FirmwareExtractor(output_dir=args.output)

    input_path = Path(args.input)
    if input_path.is_file():
        extractor.analyze_firmware_file(input_path)
    elif input_path.is_dir():
        extractor.analyze_directory(input_path)
    else:
        print(f"Input not found: {input_path}")
        sys.exit(1)

    extractor.generate_reports()
    print("\nAnalysis complete!")


if __name__ == '__main__':
    main()
