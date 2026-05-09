#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strip_renderdoc_signatures.py
------------------------------
一键去除源码中所有可被人识别为 "RenderDoc" 的特征码。
hook 注入机制保持不变；仅替换可暴露身份的字符串/宏/URL/作者信息。

用法:
    python scripts/strip_renderdoc_signatures.py [--dry-run] [--root <path>]

选项:
    --dry-run   只打印要修改的内容，不实际写入文件
    --root      项目根目录（默认为脚本所在目录的上一级）
"""

import os
import re
import sys
import argparse
import pathlib

# ============================================================
# 替换规则：(old_pattern, new_string, flags, 说明)
# 使用正则，注意转义
# ============================================================

# 目标名称配置 - 可按需修改
NEW_PRODUCT_NAME    = "SanQi Capture"
NEW_PRODUCT_SHORT   = "SQCapture"
NEW_COMPANY_NAME    = "SanQi Technology"
NEW_PRODUCT_URL     = "https://www.sanqitech.internal/"
NEW_EMAIL           = "support@sanqitech.internal"
NEW_PROCESS_NAME    = "sqcapture"  # 小写，用于文件名/进程名

RULES = [
    # ----------------------------------------------------------------
    # 1. UI 文本 / 对话框里的产品名
    # ----------------------------------------------------------------
    (r'\bRenderDoc\b', NEW_PRODUCT_NAME, 0,
     "产品名 RenderDoc → SanQi Capture (代码逻辑/UI文本中)"),

    # ----------------------------------------------------------------
    # 2. 网址 / API 文档链接
    # ----------------------------------------------------------------
    (r'https?://renderdoc\.org/?[^\s"\'<>]*', NEW_PRODUCT_URL, re.IGNORECASE,
     "renderdoc.org URL"),
    (r'https?://github\.com/baldurk/renderdoc[^\s"\'<>]*', NEW_PRODUCT_URL, re.IGNORECASE,
     "GitHub baldurk/renderdoc URL"),

    # ----------------------------------------------------------------
    # 3. 作者信息（仅替换运行时可见的，如对话框/邮件链接，跳过版权头注释）
    # 注意：版权头 "Copyright (c) ... Baldur Karlsson" 不替换（法律/溯源保留）
    # ----------------------------------------------------------------
    (r'baldurk@baldurk\.org', NEW_EMAIL, re.IGNORECASE,
     "作者邮箱（运行时可见）"),
    (r'Baldur Karlsson \(RenderDoc author\)', NEW_COMPANY_NAME, 0,
     "对话框中的作者署名"),
    # 注意：不替换通用的 "Baldur Karlsson" 以保留版权注释
    # 只替换在URL/邮件主题中出现的 baldurk（会泄漏身份）
    (r'(mailto:[^"\'<>\s]*?)baldurk(@[^"\'<>\s]*)', r'\g<1>support\g<2>', re.IGNORECASE,
     "mailto链接中的 baldurk 用户名"),

    # ----------------------------------------------------------------
    # 4. RC 资源文件里的字段（FileDescription / ProductName 等）
    #    渲染时已由 PE 伪装替换，但源码里也清理掉
    # ----------------------------------------------------------------
    (r'(VALUE\s+"FileDescription",\s*")renderdoccmd\s*-\s*https?://renderdoc\.org/(")',
     r'\g<1>' + NEW_PRODUCT_SHORT + r'\g<2>', re.IGNORECASE,
     "renderdoccmd.rc FileDescription"),
    (r'(VALUE\s+"ProductName",\s*")\s*RenderDoc\s*(")',
     r'\g<1>' + NEW_PRODUCT_NAME + r'\g<2>', re.IGNORECASE,
     "RC ProductName"),
    (r'(VALUE\s+"InternalName",\s*")\s*renderdoccmd\.exe\s*(")',
     r'\g<1>' + NEW_PROCESS_NAME + r'.exe' + r'\g<2>', re.IGNORECASE,
     "RC InternalName renderdoccmd.exe"),
    (r'(VALUE\s+"OriginalFilename",\s*")\s*renderdoccmd\.exe\s*(")',
     r'\g<1>' + NEW_PROCESS_NAME + r'.exe' + r'\g<2>', re.IGNORECASE,
     "RC OriginalFilename renderdoccmd.exe"),
    # RC 里的 CompanyName 和 LegalCopyright 如果是 Baldur Karlsson 则保留
    # (renderdoc.rc 和 qrenderdoc.rc 已伪装成 Microsoft，renderdoccmd.rc 还暴露作者)
    (r'(VALUE\s+"CompanyName",\s*")\s*Baldur Karlsson\s*(")',
     r'\g<1>' + NEW_COMPANY_NAME + r'\g<2>', 0,
     "RC CompanyName (renderdoccmd.rc)"),
    (r'(VALUE\s+"LegalCopyright",\s*")\s*Copyright[^"]*?Baldur Karlsson\s*(")',
     r'\g<1>Copyright (c) 2025 ' + NEW_COMPANY_NAME + r'\g<2>', re.IGNORECASE,
     "RC LegalCopyright (renderdoccmd.rc)"),

    # ----------------------------------------------------------------
    # 5. Python 模块名 / 程序名（仅 PythonContext 中暴露的 program_name）
    # ----------------------------------------------------------------
    (r'(static wchar_t program_name\[\]\s*=\s*L")\s*qrenderdoc\s*(")',
     r'\g<1>' + NEW_PROCESS_NAME + r'\g<2>', 0,
     "Python program_name L\"qrenderdoc\""),

    # ----------------------------------------------------------------
    # 6. Session/配置 名称（QRenderDoc → SQCapture）
    # ----------------------------------------------------------------
    (r'(session\.configData\(\)\.name\s*=\s*")\s*QRenderDoc\s*(")',
     r'\g<1>' + NEW_PRODUCT_SHORT + r'\g<2>', 0,
     "session configData name"),

    # ----------------------------------------------------------------
    # 7. Analytics 上报 URL（已在第2条覆盖，这里单独再保险一次）
    # ----------------------------------------------------------------
    (r'https?://renderdoc\.org/analytics[^\s"\'<>]*', NEW_PRODUCT_URL + 'analytics', re.IGNORECASE,
     "analytics URL"),
    (r'https?://renderdoc\.org/bugreporter[^\s"\'<>]*', NEW_PRODUCT_URL + 'bugreport', re.IGNORECASE,
     "bugreport URL"),
    (r'https?://renderdoc\.org/getupdateurl[^\s"\'<>]*',
     NEW_PRODUCT_URL + 'update', re.IGNORECASE,
     "update URL"),
    (r'https?://renderdoc\.org/tips[^\s"\'<>]*',
     NEW_PRODUCT_URL + 'tips', re.IGNORECASE,
     "tips URL"),
    (r'https?://renderdoc\.org/builds[^\s"\'<>]*',
     NEW_PRODUCT_URL + 'builds', re.IGNORECASE,
     "builds URL"),
    (r'https?://renderdoc\.org/docs[^\s"\'<>]*',
     NEW_PRODUCT_URL + 'docs', re.IGNORECASE,
     "docs URL"),

    # ----------------------------------------------------------------
    # 8. Android demo 应用包名
    # ----------------------------------------------------------------
    (r'renderdoc\.org\.demos\.arm(32|64)',
     r'sanqi.capture.demos.arm\1', re.IGNORECASE,
     "Android demo app package name"),

    # ----------------------------------------------------------------
    # 9. 邮件主题行里的 RenderDoc%20
    # ----------------------------------------------------------------
    (r'RenderDoc%20', NEW_PRODUCT_NAME.replace(' ', '%20') + '%20', 0,
     "URL编码的 RenderDoc%20"),

    # ----------------------------------------------------------------
    # 注意：以下内容故意 **不** 替换：
    #   - RENDERDOC_* 宏（C API接口，已由 stealth_remap 处理符号导出）
    #   - #include "renderdoc_app.h" 等内部头文件名
    #   - renderdoc/driver/ 路径下的目录名
    #   - VK_LAYER_RENDERDOC_Capture（已被 stealth_remap 重定向）
    #   - MAGIC_HEADER = 'RDOC'（文件格式，动一个字节会破坏向后兼容）
    #   - hook 相关代码（MinHook、IAT hook 等）
    # ----------------------------------------------------------------
]

# ============================================================
# 文件类型白名单（只处理这些后缀）
# ============================================================
INCLUDE_EXTS = {
    '.cpp', '.h', '.c', '.hpp',
    '.ui',
    '.rc',
    '.py',
}

# ============================================================
# 目录/文件黑名单（跳过，避免误伤三方库）
# ============================================================
EXCLUDE_DIRS = {
    'x64', 'x86', 'Debug', 'Release',
    '3rdparty',
    '.git',
    '__pycache__',
}

EXCLUDE_FILES = {
    # 三方 app header（只是文档/演示用）
    'renderdoc_app.h',
    # 混淆/remap 基础设施本身（里面 OBF_RENDERDOC = OBF_SYSTEM_LOAD 这种不碰）
    'string_obfuscation.h',
    'stealth_remap.h',
    # 深度反制措施（纯设计文档）
    'phase3_deep_countermeasures.h',
    # Vulkan 官方头文件
    'glext.h',
    'vulkan_core.h',
    'vulkan.h',
    'vk_mem_alloc.h',
    # 脚本自身
    'strip_renderdoc_signatures.py',
}


def should_process(path: pathlib.Path) -> bool:
    """判断文件是否需要处理"""
    # 跳过黑名单目录
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return False
    # 跳过黑名单文件
    if path.name in EXCLUDE_FILES:
        return False
    # 只处理白名单后缀
    return path.suffix.lower() in INCLUDE_EXTS


def apply_rules(text: str) -> tuple[str, list[str]]:
    """对文本应用所有替换规则，返回 (新文本, 变更说明列表)"""
    changes = []
    for old_pat, new_str, flags, desc in RULES:
        new_text, count = re.subn(old_pat, new_str, text, flags=flags)
        if count:
            changes.append(f"  [{count}处] {desc}")
            text = new_text
    return text, changes


def process_file(path: pathlib.Path, dry_run: bool) -> bool:
    """处理单个文件，返回是否有变更"""
    try:
        raw = path.read_bytes()
    except Exception as e:
        print(f"[SKIP] 读取失败: {path}: {e}")
        return False

    # 检测编码
    encoding = 'utf-8'
    for bom, enc in [(b'\xff\xfe', 'utf-16-le'), (b'\xfe\xff', 'utf-16-be'),
                     (b'\xef\xbb\xbf', 'utf-8-sig')]:
        if raw.startswith(bom):
            encoding = enc
            break

    try:
        text = raw.decode(encoding)
    except Exception:
        try:
            text = raw.decode('latin-1')
            encoding = 'latin-1'
        except Exception as e:
            print(f"[SKIP] 解码失败: {path}: {e}")
            return False

    new_text, changes = apply_rules(text)

    if not changes:
        return False

    rel = path.relative_to(path.anchor)
    print(f"\n[{'DRY' if dry_run else 'MOD'}] {path}")
    for ch in changes:
        print(ch)

    if not dry_run:
        try:
            path.write_bytes(new_text.encode(encoding))
        except Exception as e:
            print(f"  [ERROR] 写入失败: {e}")
            return False

    return True


def main():
    parser = argparse.ArgumentParser(description="去除 RenderDoc 特征码")
    parser.add_argument('--dry-run', action='store_true', help="只预览，不写入")
    parser.add_argument('--root', default=None, help="项目根目录")
    args = parser.parse_args()

    if args.root:
        root = pathlib.Path(args.root).resolve()
    else:
        root = pathlib.Path(__file__).resolve().parent.parent

    print(f"项目根目录: {root}")
    print(f"模式: {'DRY RUN（不写入）' if args.dry_run else '实际写入'}")
    print(f"新产品名: {NEW_PRODUCT_NAME}")
    print("=" * 60)

    total_files = 0
    changed_files = 0

    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if not should_process(path):
            continue
        total_files += 1
        if process_file(path, args.dry_run):
            changed_files += 1

    print("\n" + "=" * 60)
    print(f"扫描文件: {total_files}")
    print(f"{'预计' if args.dry_run else '实际'}修改: {changed_files} 个文件")
    if args.dry_run:
        print("提示: 使用不带 --dry-run 参数重新运行以实际写入。")


if __name__ == '__main__':
    main()
