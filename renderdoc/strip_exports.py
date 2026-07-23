"""Strip ALL detectable fingerprints from a PE binary.
Replaces known signatures in-place with same-length neutral strings.
Handles both ASCII and UTF-16LE (wide char) variants.

SAFETY: Only replaces bytes inside PE sections that contain strings/resources.
        Skips .text (code) and .data (initialized data with function pointers/vtables)
        to prevent mismatching binary data from being corrupted.

Safe sections (strings only):
  .rdata  - read-only data (string literals, RTTI names, export name table)
  .rsrc   - resource section (version strings, dialog text)
  .msvcjmc - just-my-code metadata (safe to patch)

Unsafe sections (skipped):
  .text   - executable code (byte patterns could accidentally match)
  .data   - initialized mutable data (vtables, function pointers)
  .pdata  - exception tables
  .reloc  - relocation table

Usage: python strip_exports.py <binary_path>
"""
import sys
import struct

dll_path = sys.argv[1]


def w(s):
    """Convert ASCII string to UTF-16LE bytes (wide char)."""
    return s.encode('utf-16-le')


def wp(pat, rep):
    """Generate a UTF-16LE replacement pair."""
    p = w(pat)
    r = w(rep)
    assert len(p) == len(r), f"Wide length mismatch: {pat!r}({len(p)}) vs {rep!r}({len(r)})"
    return (p, r)


# IMPORTANT: replacement values must NOT themselves be known signatures.
# Use neutral-looking strings that don't form a detectable pattern.
# All replacements MUST be exactly same byte length as pattern.

replacements = [

    # =========================================================
    # PHASE 0: Clean up old strip artifacts (previous pass used
    # _xxxxxxxx / _XXXDOC___ which are themselves known AC sigs)
    # Must be processed FIRST before any other rules.
    # =========================================================
    # _xxxxxxxx_sanqi\ path prefix (15 bytes)
    (b'_xxxxxxxx_sanqi', b'sqcap_lib_src__'),
    # _xxxxxxxx (9 bytes) - old renderdoc strip artifact
    (b'_xxxxxxxx', b'sqcaptlib'),
    # _XXXDOC___ (10 bytes) - old RENDERDOC_ strip artifact
    (b'_XXXDOC___', b'SQC_LAYER_'),
    # _XXXXXXXX (9 bytes) - old RENDERDOC strip artifact
    (b'_XXXXXXXX', b'SQCAPTLIB'),
    # sqcaptlib__.dll -> system_load.dll (wrong replacement artifact, 15 bytes)
    (b'sqcaptlib__.dll', b'system_load.dll'),
    # sqcaptlib__ -> system_load (wrong replacement artifact, 11 bytes)
    # NOTE: must be AFTER the .dll rule above
    (b'sqcaptlib__', b'system_load'),
    # sqcap_lib__replay__marker__ -> rename to neutral module marker (27 bytes)
    (b'sqcap_lib__replay__marker__', b'sqcap_lib__active__module__'),
    # sqcap_lib__inject__marker__ -> same neutral name (27 bytes)
    (b'sqcap_lib__inject__marker__', b'sqcap_lib__active__module__'),

    # =========================================================
    # PHASE 1: Long specific strings (longest first)
    # =========================================================

    # logcat cmd line (35 bytes)
    (b'logcat -t %u -v brief -s renderdoc:',
     b'logcat -t %u -v brief -s sqi_layer:'),

    # Android package name full (26 bytes)
    (b'org.renderdoc.renderdoccmd',
     b'com.sqcap.capture.sqcaptur'),

    # Android path prefix (23 bytes)
    (b'share/renderdoc/plugins',
     b'share/sanqi_cap/plugins'),

    # Android local abstract (24 bytes)
    (b'localabstract:renderdoc_',
     b'localabstract:sqi_layer_'),

    # /files/renderdoc.conf (21 bytes)
    (b'/files/renderdoc.conf',
     b'/files/sqcapture.conf'),

    # share/renderdoc/ (16 bytes)
    (b'share/renderdoc/',
     b'share/sqi_layer/'),

    # debug.renderdoc. (16 bytes)
    (b'debug.renderdoc.',
     b'debug.sqi_layer.'),

    # org.renderdoc. (14 bytes)
    (b'org.renderdoc.',
     b'com.sanqicap_.'),

    # renderdoc.conf (14 bytes)
    (b'renderdoc.conf',
     b'sqcapture.conf'),

    # =========================================================
    # PHASE 2: Executable/DLL file names
    # =========================================================

    # renderdoccmd.exe (16 bytes)
    (b'renderdoccmd.exe', b'sanqicapture.exe'),

    # renderdoccmd.apk (16 bytes)
    (b'renderdoccmd.apk', b'sqcapturecmd.apk'),

    # renderdoccmd (12 bytes)
    (b'renderdoccmd', b'sanqicapture'),

    # renderdocshim64.dll (19 bytes)
    (b'renderdocshim64.dll', b'system_shim64__.dll'),

    # renderdocshim32.dll (19 bytes)
    (b'renderdocshim32.dll', b'system_shim32__.dll'),

    # renderdocshim (13 bytes)
    (b'renderdocshim', b'sys_shimlib__'),

    # qrenderdoc.exe (14 bytes)
    (b'qrenderdoc.exe', b'sqcap_tool.exe'),

    # qrenderdoc (10 bytes)
    (b'qrenderdoc', b'sqcap_tool'),

    # =========================================================
    # PHASE 3: RENDERDOC_ prefix (10 bytes) - use SQC_LAYER__
    # =========================================================
    (b'RENDERDOC_', b'SQC_LAYER_'),

    # =========================================================
    # PHASE 4: renderdoc (all case variants, 9 bytes)
    # Use neutral strings that look like generic product names
    # =========================================================
    (b'renderdoc', b'sqcaptlib'),
    (b'Renderdoc', b'Sqcaptlib'),
    (b'RenderDoc', b'SqCapLib_'),
    (b'RENDERDOC', b'SQCAPTLIB'),

    # =========================================================
    # PHASE 5: Wide char (UTF-16LE) variants
    # =========================================================
    wp('RENDERDOC_', 'SQC_LAYER_'),
    wp('renderdoccmd', 'sanqicapture'),
    wp('renderdocshim', 'sys_shimlib__'),
    wp('qrenderdoc', 'sqcap_tool'),
    wp('renderdoc',  'sqcaptlib'),
    wp('Renderdoc',  'Sqcaptlib'),
    wp('RenderDoc',  'SqCapLib_'),
    wp('RENDERDOC',  'SQCAPTLIB'),

    # =========================================================
    # PHASE 6: rdoc_ prefix shader/debug variable names
    # These are injected into game shaders and visible in memory
    # =========================================================
    # debug.rdoc. property names (Android adb) - 10 bytes
    (b'debug.rdoc.', b'debug.sqc_.'),

    # rdoc_isa__ (10 bytes)
    (b'rdoc_isa__', b'sqc__isa__'),

    # rdoc_ prefix shader variables (5 bytes prefix, handle individually)
    # rdoc_invocation (15 bytes)
    (b'rdoc_invocation', b'sqcp_invocation'),
    # rdoc_meshThread (15 bytes)
    (b'rdoc_meshThread', b'sqcp_meshThread'),
    # rdoc_sampleIndex (16 bytes)
    (b'rdoc_sampleIndex', b'sqcp_sampleIndex'),
    # rdoc_primitiveIndex (19 bytes)
    (b'rdoc_primitiveIndex', b'sqcp_primitiveIndex'),
    # rdoc_instanceIndex (18 bytes)
    (b'rdoc_instanceIndex', b'sqcp_instanceIndex'),
    # rdoc_vertexIndex (16 bytes)
    (b'rdoc_vertexIndex', b'sqcp_vertexIndex'),
    # rdoc_fragCoord (14 bytes)
    (b'rdoc_fragCoord', b'sqcp_fragCoord'),
    # rdoc_meshGroup (14 bytes)
    (b'rdoc_meshGroup', b'sqcp_meshGroup'),
    # rdoc_viewIndex (14 bytes)
    (b'rdoc_viewIndex', b'sqcp_viewIndex'),
    # rdoc_as_ prefix (8 bytes) - file pattern
    (b'rdoc_as_', b'sqcp_as_'),
    # rdoc% (5 bytes) - log filename format
    (b'rdoc%', b'sqcp%'),

    # =========================================================
    # PHASE 6b: framecapture / FrameCaptur paths
    # =========================================================
    # internal/framecapture (21 bytes)
    (b'internal/framecapture', b'internal/sqcapframe__'),
    # FrameCaptur (11 bytes) - matches FrameCapture and FrameCapturing
    (b'FrameCaptur', b'SqcCapture_'),

    # =========================================================
    # PHASE 6c: Other signatures
    # =========================================================
    # SanQi Capture (13 bytes) - avoid in binary output
    (b'SanQi Capture', b'SqTechCaptlib'),

    # Source/build paths
    # sqcap_src -> null out source folder name in __FILE__ embedded paths
    (b'sqcap_src', b'\x00' * 9),  # 9 bytes -> null in embedded paths
    (b'renderdoc\\',     b'sqcaptlib\\'),        # 10 bytes
    (b'renderdoc/',      b'sqcaptlib/'),         # 10 bytes

    # __FILE__ embedded paths after renderdoc_sanqi -> sqcaptlib_sqcap rename
    # These appear in RDCASSERT/RDCERR/rdclog strings compiled into .rdata
    # Replace with NUL bytes so C-strings truncate to empty (safe for log-only paths)
    (b'E:\\work\\sqcaptlib_sqcap\\', b'\x00' * 24),  # 24 bytes -> null-truncate
    (b'E:\\work\\sqcaptlib_sqcap/', b'\x00' * 24),  # 24 bytes -> null-truncate
    # Also strip remaining E:\work\ prefix in case other variants exist
    (b'E:\\work\\sqcap',  b'\x00' * 13),  # 13 bytes -> null-truncate

    # Clean up previous pass artifacts (X:\sqcbuild prefix from old rules)
    (b'X:\\sqcbuild\\sqcap_src__\\', b'\x00' * 24),  # 24 bytes -> erase old replacement
    (b'X:\\sqcbuild\\sqcap_src__/', b'\x00' * 24),  # 24 bytes -> erase old replacement
    (b'X:\\sqcb\\sqcap',            b'\x00' * 13),  # 13 bytes -> erase old replacement

    # =========================================================
    # PHASE 6b: system_load DLL name fingerprints
    # NOTE: Do NOT strip system_load__replay__marker — it is the detection
    # marker used by LibraryHooks::Detect in win32_libentry.cpp to identify
    # tool/replay processes and skip hook/stealth installation. Stripping it
    # causes tool processes to go through full anti-detection, breaking them.
    # =========================================================
    # Clean up any old replay/inject marker artifacts
    (b'sqcap_lib__replay__marker__', b'sqcap_lib__active__module__'),  # 27 bytes
    (b'sqcap_lib__inject__marker__', b'sqcap_lib__active__module__'),  # 27 bytes

    # =========================================================
    # PHASE 7: rdc* internal type names (SWIG / error messages)
    # =========================================================
    (b'rdcarray', b'sqcarray'),
    (b'rdcpair',  b'sqcpair'),
    (b'rdcstr',   b'sqcstr'),
    (b'rdcfile',  b'sqcfile'),
    (b'RDCFile',  b'SqcFile'),
    (b'RDCFILE',  b'SQCFILE'),
    (b'rdocself', b'sqcself_'),

    # rdcspv namespace (6 bytes)
    (b'rdcspv', b'sqcspv'),

    # rdcfixedarrayT (14 bytes) - RTTI/SWIG type descriptor
    (b'rdcfixedarrayT', b'sqcfixedarrayT'),
    # rdcfixedarray (13 bytes)
    (b'rdcfixedarray', b'sqcfixedarr__'),

    # rdocCaptureSettings, rdocConfigData, rdocPerformance, rdocFilter, rdocLayout (qrenderdoc SWIG names)
    (b'rdocCapture',  b'sqcpCapture'),
    (b'rdocConfig',   b'sqcpConfig'),
    (b'rdocPerfor',   b'sqcpPerfor'),
    (b'rdocFilter',   b'sqcpFilter'),
    (b'rdocLayout',   b'sqcpLayout'),

    # Error message strings with RDC
    (b'Native RDC capture', b'Native SQC capture'),
    (b'RDC capture',        b'SQC capture'),
    (b'RDC file',           b'SQC file'),

    # Log path format string
    (b'rdoc_%llu_%llu.bin', b'sqcp_%llu_%llu.bin'),

    # Config directory (written to roaming appdata)
    (rb'\renderdoc\renderdoc', rb'\sanqiapp_\sqcaptur_'),  # 20 bytes

    # RDOC prefix variants
    (b'RDOC_BASE',  b'SQC__BASE'),
    (b'RDOC ',      b'SQC_ '),
    (b'RDOC\x00',   b'SQC_\x00'),
    (b'RDCDriver',  b'SqcDriver'),
    (b'RDCEraseEl', b'SqcEraseEl'),
    (b'RDCLOG',     b'SQCLOG'),
    (b'RDCERR',     b'SQCERR'),
    (b'RDCWARN',    b'SQCWRN_'),
    (b'RDCDEBUG',   b'SQCDBUG_'),
    (b'RDCASSERT',  b'SQCASERT_'),

    # Overlay
    (b'overlay', b'sqcover'),
    (b'Overlay', b'Sqcover'),

    # D3D11 wrapper/proxy
    (b'WrappedID3D11',    b'SqcWrapD3D11_'),
    (b'WrappedID3D12',    b'SqcWrapD3D12_'),
    (b'ProxyBridge',      b'SqcBridge__'),
    (b'Proxy_D3D11',      b'SqcP_D3D11_'),
    (b'd3d11_proxy_trace', b'sqc_d3d11_trace__'),
    (b'd3d11_hooks',      b'sqc_d3dhks_'),
    (b'D3D11Hook',        b'SqcD3DHk_'),

    # Hook/capture strings
    (b'HOOK_LOG',    b'SQC__LOG'),
    (b'hook.log',    b'sqc_.log'),

    # Vulkan layer
    (b'VK_LAYER_MICROSOFT_SystemLoad', b'VK_LAYER_SQC___SqcLayerVk____'),
    (b'VK_LAYER_SANQI', b'VK_LAYER_SQC__'),
    (b'VK_LAYER',       b'VK_SQCAP'),
    # After VK_LAYER->VK_SQCAP transforms, residual SystemLoad in function names
    (b'VK_SQCAP_SQC___SystemLoad____', b'VK_SQCAP_SQC___SqcLayerVk____'),

    # PDB path
    (b'd3d11_proxy.pdb', b'sqc_d3d11__.pdb'),
    (b'system_load.pdb', b'sqclib_data.pdb'),   # 15 bytes

    # =========================================================
    # PHASE 7b: Author / origin fingerprints
    # These appear in .rdata (debug strings) and .rsrc (version resource)
    # =========================================================

    # Author name embedded in debug strings and version resource
    (b'Baldur Karlsson', b'SqC_Team_Author'),   # 15 bytes
    # Short author handle in GitHub URLs (github.com/baldurk/...)
    (b'baldurk',         b'sqcusr_'),            # 7 bytes
    # Crytek copyright line in source-embedded strings
    (b'Crytek',          b'SqcLab'),             # 6 bytes

    # sqcaptlib residue in embedded source paths and internal strings
    # (old project name, appears in android paths, internal protocol strings)
    (b'sqcaptlib',       b'sqcaplib_'),          # 9 bytes

    # Build output path fragment exposed via PDB debug directory
    (b'x64\\Release',    b'x64\\SqcData'),       # 11 bytes

    # Internal API function names that reveal capture semantics
    # NOTE: CaptureFile/INTERNAL_SetCaptureFile are exported function names -
    # renaming them breaks EXE->DLL linking. Do NOT replace these.

    # =========================================================
    # PHASE 8: UTF-16LE other key signatures
    # =========================================================
    wp('RENDERDOC_',     'SQC_LAYER_'),
    wp('VK_LAYER_RENDERDOC_Capture', 'VK_LAYER_SQCAPTURE_Capture'),
    wp('VK_LAYER',       'VK_SQCAP'),

    # =========================================================
    # PHASE 9: Remaining rdc*/RDC* signatures
    # =========================================================

    # SWIG/Python binding type names (qsanqiInjectTool.exe)
    (b'rdcinflexiblestr', b'sqcinflexiblestr'),  # 16 bytes
    (b'rdcdatetime',      b'sqcdatetime'),        # 11 bytes

    # HLSL embedded shader macro names (system_load.dll, d3d11_proxy.dll)
    (b'RDCMAX', b'SQCMAX'),   # 6 bytes
    (b'RDCMIN', b'SQCMIN'),   # 6 bytes

    # OpenGL enum helper embedded in shader source
    (b'RDCGLenum', b'SqcGLenum'),  # 9 bytes

    # Source file path in embedded debug/assert strings
    (b'rdcbytetrie', b'sqcbytetrie'),  # 11 bytes

    # Standalone RDC references in docstrings
    (b'native RDC ', b'native SQC '),  # 11 bytes
    (b'native RDC.', b'native SQC.'),  # 11 bytes
    (b'native RDC\n', b'native SQC\n'), # 11 bytes
    (b'in the RDC.', b'in the SQC.'),  # 11 bytes
    (b' native RDC', b' native SQC'),  # 11 bytes

    # =========================================================
    # PHASE 10: SanQi / SanQiCapture brand strings
    # (AC can detect tool brand names too)
    # =========================================================

    # ASCII brand strings
    (b'SanQiCapture', b'SqcapCapture'),        # 12 bytes — assert messages
    (b'SanQi Technology', b'SqTech_Platform_'), # 16 bytes — PE version resource
    (b'SanQi_Restore', b'SqCap_Restore'),       # 13 bytes — registry backup
    # SanQi_app (9 bytes)
    (b'SanQi_app', b'SqCap_app'),               # 9 bytes — android debug prop

    # Wide char (UTF-16LE) brand strings — PE version resource and COM registry
    wp('SanQiCapture',    'SqcapCapture'),
    wp('SanQi Capture',   'SqTechCaptlib'),
    wp('SanQi Technology','SqTech_Platform_'),
    wp('SanQi_Restore',   'SqCap_Restore'),
    wp('SanQi_app',       'SqCap_app'),

    # COM ProgID in wide: SanQi Capture.RDCCapture.1 -> SqTechCaptlib.SQCCapture.1
    wp('RDCCapture', 'SQCCapture'),  # 10 bytes wide

    # =========================================================
    # PHASE 11: Remaining sanqi* brand strings
    # =========================================================

    # sanqicapture (12 bytes) — Android adb shell commands
    # e.g. "am start -n sanqicapture remoteserver"
    (b'sanqicapture', b'sqcaptool___'),

    # sanqitech (9 bytes) — URL/email strings in qsanqiInjectTool.exe
    # e.g. "href=\"https://www.sanqitech.internal\""
    (b'sanqitech', b'sqcaptech'),

    # SanQi (5 bytes) — catch any remaining case-mixed brand fragments
    (b'SanQi', b'SqCap'),

    # sanqi (5 bytes) — lowercase fragments
    (b'sanqi', b'sqcap'),

    # =========================================================
    # PHASE 11b: Wide char (UTF-16LE) sanqi* variants
    # =========================================================
    # sanqicapture (wide, 12 chars = 24 bytes)
    wp('sanqicapture', 'sqcaptool___'),
    # sanqitech (wide, 9 chars = 18 bytes)
    wp('sanqitech', 'sqcaptech'),
    # SanQi (wide, 5 chars = 10 bytes) — catch remaining mixed case
    wp('SanQi', 'SqCap'),
    # sanqi (wide, 5 chars = 10 bytes)
    wp('sanqi', 'sqcap'),
]

# Validate all lengths
for pat, rep in replacements:
    assert len(pat) == len(rep), f"Length mismatch: {pat!r}({len(pat)}) vs {rep!r}({len(rep)})"


def parse_pe_safe_ranges(data: bytes) -> list[tuple[int, int]]:
    """
    Parse PE sections and return list of (start, end) file-offset ranges
    that are safe to do string replacement in.

    Safe: .rdata, .rsrc, .msvcjmc, _RDATA
    Unsafe (skipped): .text, .data, .pdata, .reloc
    """
    if len(data) < 0x40:
        return [(0, len(data))]

    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    if e_lfanew + 24 > len(data):
        return [(0, len(data))]

    pe_sig = data[e_lfanew:e_lfanew+4]
    if pe_sig != b'PE\x00\x00':
        return [(0, len(data))]

    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    section_table_offset = e_lfanew + 24 + opt_header_size

    # .rsrc contains binary resource directory structures (IMAGE_RESOURCE_DIRECTORY,
    # IMAGE_RESOURCE_DIRECTORY_ENTRY) whose integer fields can be corrupted by pattern
    # replacement. However, embedded HLSL shader sources in .rsrc contain RENDERDOC_
    # function name strings that are AC scan targets. Since our replacement rules are
    # all ASCII text patterns that cannot accidentally match binary integer fields,
    # we include .rsrc in the safe scan range.
    SAFE_SECTIONS = {b'.rdata', b'.msvcjmc', b'_RDATA', b'.rsrc'}
    UNSAFE_SECTIONS = {b'.text', b'.data', b'.pdata', b'.reloc', b'.tls'}

    safe_ranges = []

    for i in range(num_sections):
        sec_off = section_table_offset + i * 40
        if sec_off + 40 > len(data):
            break

        raw_name = data[sec_off:sec_off+8]
        name = raw_name.rstrip(b'\x00')

        raw_size = struct.unpack_from('<I', data, sec_off + 16)[0]
        raw_offset = struct.unpack_from('<I', data, sec_off + 20)[0]

        if name in UNSAFE_SECTIONS:
            print(f'  [SKIP] {name.decode(errors="replace"):12s} file=[0x{raw_offset:08X}, 0x{raw_offset+raw_size:08X})')
            continue

        if name in SAFE_SECTIONS or name not in UNSAFE_SECTIONS:
            if raw_offset > 0 and raw_size > 0:
                print(f'  [SCAN] {name.decode(errors="replace"):12s} file=[0x{raw_offset:08X}, 0x{raw_offset+raw_size:08X})')
                safe_ranges.append((raw_offset, raw_offset + raw_size))

    # PE headers contain binary metadata (DataDirectory, section table, etc.)
    # Never scan them — a pattern match here would corrupt RVA offsets and
    # break FindResource, GetProcAddress, and other loader operations.
    return safe_ranges


def replace_in_ranges(data: bytearray, pat: bytes, rep: bytes,
                      ranges: list[tuple[int, int]]) -> int:
    count = 0
    plen = len(pat)
    for (start, end) in ranges:
        idx = start
        while True:
            pos = data.find(pat, idx, end)
            if pos == -1:
                break
            data[pos:pos+plen] = rep
            count += 1
            idx = pos + plen
    return count


print(f'Parsing PE sections in {dll_path}...')
with open(dll_path, 'r+b') as f:
    raw = bytearray(f.read())

safe_ranges = parse_pe_safe_ranges(bytes(raw))

if not safe_ranges:
    print('WARNING: No safe ranges found, falling back to full-file scan (UNSAFE)')
    safe_ranges = [(0, len(raw))]

print(f'Applying {len(replacements)} replacement rules across {len(safe_ranges)} safe range(s)...')
total = 0
for pat, rep in replacements:
    count = replace_in_ranges(raw, pat, rep, safe_ranges)
    if count > 0:
        label = pat.decode('ascii', errors='replace')[:30]
        print(f'  {label:32s} : {count} hits')
    total += count

with open(dll_path, 'r+b') as f:
    f.write(raw)

print(f'Total: {total} replacements in {dll_path}')

# =========================================================
# PHASE EXTRA: Patch .data section for RTTI type name strings
# .data is skipped in safe_ranges (contains vtables/function pointers)
# but MSVC RTTI mangled names (AEBVrdcstr@@, etc.) are also in .data
# and contain recognizable type names. We do a targeted replacement
# of KNOWN safe type-name substrings only.
# =========================================================
data_type_replacements = [
    (b'rdcstr', b'sqcstr'),   # 6 bytes - RTTI mangled names only
]

def find_data_section_range(dll_bytes):
    e_lfanew = struct.unpack_from('<I', dll_bytes, 0x3C)[0]
    num_sec = struct.unpack_from('<H', dll_bytes, e_lfanew + 4 + 2)[0]
    opt_size = struct.unpack_from('<H', dll_bytes, e_lfanew + 4 + 16)[0]
    sec_tab = e_lfanew + 4 + 20 + opt_size
    for i in range(num_sec):
        s = sec_tab + i * 40
        name = dll_bytes[s:s+8].rstrip(b'\x00')
        if name == b'.data':
            raw_size = struct.unpack_from('<I', dll_bytes, s + 16)[0]
            raw_off = struct.unpack_from('<I', dll_bytes, s + 20)[0]
            return (raw_off, raw_off + raw_size)
    return None

with open(dll_path, 'r+b') as f:
    raw2 = bytearray(f.read())
    data_range = find_data_section_range(bytes(raw2))
    if data_range:
        extra_total = 0
        for pat, rep in data_type_replacements:
            count = replace_in_ranges(raw2, pat, rep, [data_range])
            if count > 0:
                print(f'  [.data] {pat.decode()!r:20s} : {count} hits')
                extra_total += count
        if extra_total > 0:
            f.seek(0)
            f.write(bytes(raw2))
            print(f'Extra .data patches: {extra_total}')
