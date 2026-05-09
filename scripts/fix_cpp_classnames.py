#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 C++ 符号上下文中的 'SanQi Capture'（含空格，非法类名）改为 'SanQiCapture'
字符串字面量内的 'SanQi Capture' 保持不变（产品名显示用）
"""
import re
import pathlib

ROOT = pathlib.Path("E:/work/renderdoc_sanqi")
INCLUDE_EXTS = {'.cpp', '.h', '.c', '.hpp'}
EXCLUDE_DIRS = {'x64', 'x86', 'Debug', 'Release', '3rdparty', '.git', '__pycache__'}
EXCLUDE_FILES = {'strip_renderdoc_signatures.py', 'fix_cpp_classnames.py'}

CPP_PATTERNS = [
    (r'\bclass\s+SanQi\s+Capture\b',    'class SanQiCapture'),
    (r'\bstruct\s+SanQi\s+Capture\b',   'struct SanQiCapture'),
    (r'\bSanQi\s+Capture\s*::',          'SanQiCapture::'),
    (r'::\s*SanQi\s+Capture\b',          '::SanQiCapture'),
    (r'\bSanQi\s+Capture\s*&',           'SanQiCapture &'),
    (r'\bSanQi\s+Capture\s*\*',          'SanQiCapture *'),
    (r'\bSanQi\s+Capture\s*\(',          'SanQiCapture('),
    (r'<\s*SanQi\s+Capture\s*>',         '<SanQiCapture>'),
    # 变量/参数声明：static SanQi Capture xxx 或 return/函数参数中的类型名
    (r'\bstatic\s+SanQi\s+Capture\b',    'static SanQiCapture'),
    (r'\bconst\s+SanQi\s+Capture\b',     'const SanQiCapture'),
    (r'\bvirtual\s+SanQi\s+Capture\b',   'virtual SanQiCapture'),
    (r'\breturn\s+SanQi\s+Capture\b',    'return SanQiCapture'),
    # 通用：SanQi Capture 后跟合法标识符（变量名）= 类型声明
    (r'\bSanQi\s+Capture\s+([a-zA-Z_]\w*)',  r'SanQiCapture \1'),
]


def fix_code_segment(seg: str) -> str:
    for pat, rep in CPP_PATTERNS:
        seg = re.sub(pat, rep, seg)
    return seg


def fix_line(line: str) -> str:
    result = []
    i = 0
    in_string = False
    string_char = ''
    seg_start = 0

    while i < len(line):
        c = line[i]
        if not in_string:
            if c in ('"', "'"):
                # 输出前面的代码段（需要替换）
                result.append(fix_code_segment(line[seg_start:i]))
                in_string = True
                string_char = c
                seg_start = i
            elif c == '/' and i + 1 < len(line) and line[i + 1] == '/':
                # 行注释：代码部分替换，注释部分原样
                result.append(fix_code_segment(line[seg_start:i]))
                result.append(line[i:])  # 注释保留原样
                return ''.join(result)
        else:
            # 在字符串内
            if c == string_char and (i == 0 or line[i - 1] != '\\'):
                # 字符串结束：原样输出
                result.append(line[seg_start:i + 1])
                in_string = False
                seg_start = i + 1
        i += 1

    # 处理剩余
    remaining = line[seg_start:]
    if in_string:
        result.append(remaining)  # 未闭合字符串原样
    else:
        result.append(fix_code_segment(remaining))
    return ''.join(result)


def process_file(path: pathlib.Path) -> bool:
    try:
        raw = path.read_bytes()
    except Exception:
        return False

    enc = 'utf-8'
    for bom, e in [(b'\xff\xfe', 'utf-16-le'), (b'\xfe\xff', 'utf-16-be'), (b'\xef\xbb\xbf', 'utf-8-sig')]:
        if raw.startswith(bom):
            enc = e
            break
    try:
        text = raw.decode(enc)
    except Exception:
        try:
            text = raw.decode('latin-1')
            enc = 'latin-1'
        except Exception:
            return False

    if 'SanQi Capture' not in text:
        return False

    lines = text.split('\n')
    new_lines = [fix_line(l) for l in lines]
    new_text = '\n'.join(new_lines)

    if new_text == text:
        return False

    path.write_bytes(new_text.encode(enc))
    return True


def main():
    total = 0
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        if any(p in EXCLUDE_DIRS for p in path.parts):
            continue
        if path.name in EXCLUDE_FILES:
            continue
        if path.suffix.lower() not in INCLUDE_EXTS:
            continue
        if process_file(path):
            total += 1
            print(f"Fixed: {path.relative_to(ROOT)}")
    print(f"\nTotal: {total} files fixed")


if __name__ == '__main__':
    main()
