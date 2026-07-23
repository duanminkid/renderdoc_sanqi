#!/usr/bin/env python3
"""
Post-build TLS patcher for system_load.dll

Zeroes the TLS callback pointer in the PE header so that NO TLS callbacks
execute before DllMain. This is critical for ACE anti-cheat compatibility.

ACE反作弊系统会在DLL加载时扫描TLS回调表。如果存在TLS回调，ACE会在
DllMain执行之前就检测到我们的DLL并将其终止。此脚本将TLS回调指针清零，
使加载器跳过TLS回调阶段，直接进入DllMain。

Usage:
    python patch_tls.py <path-to-dll>

    Or as a post-build step on Windows (no Python required):
    - The script can be run from MSBuild post-build event
    - Or from a batch file after manual build
"""

import struct
import sys
import os


def patch_tls(dll_path):
    """Patch TLS callback pointer to NULL in the specified DLL."""

    if not os.path.isfile(dll_path):
        print(f"ERROR: File not found: {dll_path}")
        return False

    with open(dll_path, 'rb') as f:
        data = bytearray(f.read())

    # --- Parse PE headers ---
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    pe_sig = struct.unpack_from('<I', data, e_lfanew)[0]

    if pe_sig != 0x4550:  # "PE\0\0"
        print(f"ERROR: Not a valid PE file (sig=0x{pe_sig:08X})")
        return False

    coff = e_lfanew + 4
    machine = struct.unpack_from('<H', data, coff)[0]
    sections = struct.unpack_from('<H', data, coff + 2)[0]
    optsize = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]

    if magic == 0x10b:
        print("ERROR: PE32 is unsupported; the stealth payload is x64-only")
        return False
    elif magic == 0x20b:
        print(f"PE32+ (64-bit) - {sections} sections")
    else:
        print(f"ERROR: Unknown PE magic 0x{magic:04X}")
        return False

    # --- TLS directory (index 9) ---
    data_dir_offset = opt + 0x70
    tls_rva = struct.unpack_from('<I', data, data_dir_offset + 9 * 8)[0]
    tls_size = struct.unpack_from('<I', data, data_dir_offset + 9 * 8 + 4)[0]

    if tls_rva == 0 or tls_size == 0:
        print("No TLS directory - nothing to patch")
        return True  # Not an error - no TLS at all

    print(f"TLS directory: RVA=0x{tls_rva:X}, Size=0x{tls_size:X}")

    # --- Convert RVA to file offset ---
    sec_hdr = opt + optsize

    def rva_to_raw(rva):
        for i in range(sections):
            sh = sec_hdr + i * 40
            va = struct.unpack_from('<I', data, sh + 12)[0]
            vs = struct.unpack_from('<I', data, sh + 8)[0]
            rp = struct.unpack_from('<I', data, sh + 20)[0]
            rs = struct.unpack_from('<I', data, sh + 16)[0]
            if va <= rva < va + vs:
                return rp + (rva - va)
        return None

    tls_raw = rva_to_raw(tls_rva)
    if tls_raw is None:
        print(f"ERROR: Cannot map TLS RVA 0x{tls_rva:X} to file offset")
        return False

    if tls_raw + 32 > len(data):
        print(f"ERROR: TLS directory at 0x{tls_raw:X} exceeds file bounds")
        return False

    # --- Read and patch AddressOfCallBacks ---
    # PE32+ TLS directory layout:
    #   Offset 0: QWORD StartAddressOfRawData
    #   Offset 8: QWORD EndAddressOfRawData
    #   Offset 16: QWORD AddressOfIndex
    #   Offset 24: QWORD AddressOfCallBacks  <-- PATCH THIS
    #   Offset 32: DWORD SizeOfZeroFill
    #   Offset 36: DWORD Characteristics

    cb_field_offset = tls_raw + 24
    old_value = struct.unpack_from('<Q', data, cb_field_offset)[0]

    if old_value == 0:
        print("TLS callbacks already disabled (AddressOfCallBacks = 0)")
        return True

    # Zero it out
    struct.pack_into('<Q', data, cb_field_offset, 0)

    # --- Fix checksum if present ---
    # Checksum is at opt+64 (DWORD)
    # Security directory is data dir index 4
    sec_rva = struct.unpack_from('<I', data, data_dir_offset + 4 * 8)[0]
    if sec_rva == 0:
        # No Authenticode signature - safe to zero the checksum
        struct.pack_into('<I', data, opt + 64, 0)

    # --- Write back ---
    with open(dll_path, 'wb') as f:
        f.write(data)

    print(f"Patched! TLS AddressOfCallBacks: 0x{old_value:X} → 0 (NULL)")
    print(f"Effect: Loader will skip TLS callbacks, jump straight to DllMain")
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python patch_tls.py <path-to-dll>")
        print("")
        print("Example:")
        print("  python patch_tls.py x64\\Development\\system_load.dll")
        sys.exit(1)

    dll_path = sys.argv[1]
    print(f"Patching TLS for: {dll_path}")

    success = patch_tls(dll_path)
    if success:
        print("OK - TLS patched successfully")
    else:
        print("FAILED - TLS patching error")
        sys.exit(1)
