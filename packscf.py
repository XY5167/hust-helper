#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCF 部署包打包脚本 —— 一条命令把后端同步为桌面 fn.zip

用法：
    python packscf.py

为什么不直接 zip worker/scf/：
    腾讯云 SCF 的函数入口是【zip 根目录的 index.js】。
    若包内是 worker/scf/index.js 这种子路径，SCF 找不到入口，
    部署会静默失败（线上永远停在旧版本、新路由 404）。
    所以本脚本把 worker/scf/index.js 写到 zip 的【根】index.js，
    再并入 package.json + scf_bootstrap 这两个必需文件。

产物：C:/Users/xy516/Desktop/fn.zip（用户每次在 SCF 控制台上传的就是它）
"""
import os
import re
import shutil
import sys
import time
import zipfile

REPO = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(REPO, 'worker', 'scf')
OUT = 'C:/Users/xy516/Desktop/fn.zip'
BAK = 'C:/Users/xy516/Desktop/fn.zip.bak'

# zip 内的条目名 -> 磁盘上的来源文件
ENTRIES = [
    ('index.js', os.path.join(SRC, 'index.js')),
    ('package.json', os.path.join(SRC, 'package.json')),
    ('scf_bootstrap', os.path.join(SRC, 'scf_bootstrap')),
]


def fail(msg):
    print('[FAIL] ' + msg)
    sys.exit(1)


def main():
    # 1. 检查源文件齐全
    for name, path in ENTRIES:
        if not os.path.exists(path):
            fail('缺少源文件: %s' % path)

    backend = open(ENTRIES[0][1], encoding='utf-8').read()
    m = re.search(r"const VERSION = '([^']+)'", backend)
    version = m.group(1) if m else '(未找到 VERSION)'

    # 2. 滚动备份现有桌面包（只留一份 .bak，不堆时间戳垃圾）
    if os.path.exists(OUT):
        try:
            shutil.copy2(OUT, BAK)
            print('[BAK ] 旧包已备份 -> %s' % BAK)
        except Exception as e:
            print('[WARN] 备份失败（继续打包）: %s' % e)

    # 3. 重写 zip：根 index.js + package.json + scf_bootstrap
    try:
        with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, path in ENTRIES:
                z.write(path, name)
    except PermissionError:
        fail('无法写入 %s（文件被占用？关掉资源管理器预览或重命名旧包再试）' % OUT)

    # 4. 回读校验：结构 + 版本 + 关键路由特征
    z = zipfile.ZipFile(OUT)
    names = z.namelist()
    body = z.read('index.js')

    if 'index.js' not in names:
        fail('打包结构错误：zip 根目录缺少 index.js（SCF 会部署失败）')
    if any(n.startswith('worker/') for n in names):
        fail('打包结构错误：zip 内出现 worker/ 子路径，SCF 找不到入口')

    require_markers = [b"const VERSION = '" + version.encode() + b"'"]
    missing = [mk.decode('utf-8', 'ignore') for mk in require_markers if mk not in body]
    if missing:
        fail('回读校验失败，index.js 内未找到：%s' % ', '.join(missing))

    print()
    print('=' * 56)
    print('  打包完成  %s' % time.strftime('%Y-%m-%d %H:%M:%S'))
    print('=' * 56)
    print('  产物     : %s' % OUT)
    print('  大小     : %d bytes' % os.path.getsize(OUT))
    print('  后端版本 : %s' % version)
    print('  zip 内容 :')
    for n in names:
        print('      - %-16s %7d bytes' % (n, z.getinfo(n).file_size))
    print()
    print('  下一步：SCF 控制台 -> 上传该 fn.zip -> 部署')
    print('  验证  ：curl <SCF地址>/health  应返回 version=%s' % version)
    print('=' * 56)


if __name__ == '__main__':
    main()
