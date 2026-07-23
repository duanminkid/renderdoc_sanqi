#!/usr/bin/env python3

import ast
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BASE = "com.sqcap.capture.sqcaptur"
EXPECTED_JAVA_PATH = "com/sqcap/capture/sqcaptur"
EXPECTED_INTENT_EXTRA = "sqcaptool___"


def require_pattern(relative_path: str, pattern: str, description: str) -> None:
    path = ROOT / relative_path
    contents = path.read_text(encoding="utf-8")
    if re.search(pattern, contents) is None:
        raise RuntimeError(f"{relative_path}: missing {description}")


def get_strip_source_patterns():
    path = ROOT / "renderdoc/strip_exports.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    patterns = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and node.elts:
            source = node.elts[0]
            if isinstance(source, ast.Constant) and isinstance(source.value, bytes):
                patterns.add(source.value.decode("ascii", errors="ignore"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "wp"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            patterns.add(node.args[0].value)

    return patterns


def main() -> int:
    require_pattern(
        "renderdoc/common/globalconfig.h",
        rf'#define\s+RENDERDOC_ANDROID_PACKAGE_BASE\s+"{re.escape(EXPECTED_BASE)}"',
        f'package base "{EXPECTED_BASE}"',
    )
    require_pattern(
        "renderdoc/common/globalconfig.h",
        rf'#define\s+RENDERDOC_ANDROID_INTENT_EXTRA\s+"{re.escape(EXPECTED_INTENT_EXTRA)}"',
        f'intent extra "{EXPECTED_INTENT_EXTRA}"',
    )
    require_pattern(
        "renderdoccmd/CMakeLists.txt",
        rf'set\(RENDERDOC_ANDROID_PACKAGE_NAME\s+"{re.escape(EXPECTED_BASE)}\.\$\{{ABI_EXTENSION_NAME\}}"\)',
        "ABI-specific APK package name",
    )

    cmake = (ROOT / "renderdoccmd/CMakeLists.txt").read_text(encoding="utf-8")
    expected_path_uses = (
        f"src/{EXPECTED_JAVA_PATH}/Loader.java",
        f"obj/{EXPECTED_JAVA_PATH}/${{ABI_EXTENSION_NAME}}/*.class",
        f"src/{EXPECTED_JAVA_PATH}/*.java",
    )
    for expected in expected_path_uses:
        if expected not in cmake:
            raise RuntimeError(f"renderdoccmd/CMakeLists.txt: missing Java package path {expected}")

    package_glob = rf"{re.escape(EXPECTED_BASE)}\.\*\.apk"
    for script in (
        "renderdoc/util/buildscripts/scripts/make_package_win32.sh",
        "util/buildscripts/scripts/make_package_win32.sh",
    ):
        require_pattern(script, package_glob, "SqCap Android APK packaging glob")

    for installer in (
        "renderdoc/util/installer/Installer32.wxs",
        "renderdoc/util/installer/Installer64.wxs",
        "util/installer/Installer32.wxs",
        "util/installer/Installer64.wxs",
    ):
        require_pattern(
            installer,
            rf"{re.escape(EXPECTED_BASE)}\.arm32\.apk",
            "arm32 APK installer entry",
        )
        require_pattern(
            installer,
            rf"{re.escape(EXPECTED_BASE)}\.arm64\.apk",
            "arm64 APK installer entry",
        )

    for remote_test in (
        "renderdoc/util/test/rdtest/remoteserver.py",
        "util/test/rdtest/remoteserver.py",
    ):
        require_pattern(
            remote_test,
            rf"ADRD_SERVER_APP64\s*=\s*['\"]{re.escape(EXPECTED_BASE)}\.arm64['\"]",
            "arm64 Android remote-test package",
        )

    require_pattern(
        "renderdoc/android/android.cpp",
        r"RENDERDOC_ANDROID_INTENT_EXTRA\s+\" remoteserver\"",
        "Android server intent extra",
    )
    require_pattern(
        "renderdoccmd/renderdoccmd_android.cpp",
        rf'NewStringUTF\("{re.escape(EXPECTED_INTENT_EXTRA)}"\)',
        "Android intent-extra reader",
    )

    for pattern in get_strip_source_patterns():
        if pattern in EXPECTED_BASE or pattern in EXPECTED_INTENT_EXTRA:
            raise RuntimeError(
                f'final Android identities must not contain post-build pattern "{pattern}"'
            )

    print(f"Android package identity is consistent: {EXPECTED_BASE}.<abi>")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
