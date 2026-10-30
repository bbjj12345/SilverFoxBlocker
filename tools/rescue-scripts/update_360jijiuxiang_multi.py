# -*- coding: utf-8 -*-
"""
360 系统急救箱 半自动更新脚本

- 独立版(compkill)：从官网/宝库抓取，版本比对，手动多选下载
- WinPE 版：下载链接固定，直接下载 32/64 两个文件
- 下载完成后逐个调用 Extract.bat 解压
"""

import os
import re
import ssl
import sys
import base64
import subprocess
from urllib.request import urlopen, Request

ssl._create_default_https_context = ssl._create_unverified_context

# ==========================================
# 配置
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ARIA2C_CMD = os.path.join(
    SCRIPT_DIR, "aria2-1.37.0-win-64bit-build1", "aria2c.exe"
)
EXTRACT_BAT = os.path.join(SCRIPT_DIR, "Extract.bat")

# ---- 独立版：动态来源 ----
SOURCES = [
    {"name": "官网",     "url": "https://weishi.360.cn/jijiuxiang/index.html"},
    {"name": "软件宝库", "url": "https://baoku.360.cn/aqsd/221.html"},
]

# ---- WinPE 版：固定链接 ----
WINPE_FIXED = [
    {"name": "SuperKillerWinPE.zip",   "url": "https://down.360safe.com/SuperKillerWinPE.zip",   "bits": "32位"},
    {"name": "SuperKillerWinPE64.zip", "url": "https://down.360safe.com/SuperKillerWinPE64.zip", "bits": "64位"},
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    )
}

COMPKILL_NAME_RE = re.compile(
    r"360c[0o]mpkill_?5\.1\.(\d+)\.(\d{4})-\d{4}\.zip",
    re.IGNORECASE,
)
PATH_RE = re.compile(
    r"((?://|https?://)[^\"'\s<>]*?/)?"
    r"(360c[0o]mpkill_?5\.1\.\d+\.\d{4}-\d{4}\.zip)",
    re.IGNORECASE,
)
BUDATA_RE = re.compile(r'bu-data="([^"]+)"')


# ==========================================
# 工具函数
# ==========================================
def fetch_html(url: str) -> str:
    try:
        req = Request(url, headers=HEADERS)
        with urlopen(req, timeout=30) as resp:
            raw = resp.read()
        for enc in ("utf-8", "gbk", "gb18030"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  [warn] 抓取失败 {url} -> {e}")
        return ""


def decode_budata(b64: str) -> str:
    parts = b64.split("|||")
    decoded = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        try:
            pad = (-len(p)) % 4
            raw = base64.b64decode(p + "=" * pad)
            decoded.append(raw.decode("utf-8", errors="ignore"))
        except Exception:
            decoded.append("")
    if not decoded:
        return ""
    head = decoded[0]
    rest = decoded[1:]
    if head.endswith(":") or head.endswith("://"):
        return head + "//" + "/".join(rest)
    if head.startswith("//"):
        return "https:" + head
    return head + "/" + "/".join(rest)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("//"):
        return "https:" + raw
    return raw


def parse_compkill(name: str):
    m = COMPKILL_NAME_RE.search(name)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def bits_from_x(x: int) -> str:
    if x == 0:
        return "32位"
    if x == 64:
        return "64位"
    return f"未知(x={x})"


def scan_local_compkill(directory: str):
    """返回 {'32': (yyyy, name) or None, '64': ...}"""
    local = {"32": None, "64": None}
    for name in os.listdir(directory):
        if not name.lower().endswith(".zip"):
            continue
        low = name.lower()
        if not (low.startswith("360c0mpkill") or low.startswith("360compkill")):
            continue
        p = parse_compkill(name)
        if not p:
            continue
        x, yyyy = p
        key = "32" if x == 0 else ("64" if x == 64 else None)
        if not key:
            continue
        old = local[key]
        if old is None or yyyy > old[0]:
            local[key] = (yyyy, name)
    return local


def scan_local_winpe(directory: str):
    """
    检查本地是否存在 WinPE 固定文件名。
    返回 {'32': True/False, '64': True/False}
    """
    result = {"32": False, "64": False}
    for w in WINPE_FIXED:
        if os.path.exists(os.path.join(directory, w["name"])):
            key = "32" if w["bits"] == "32位" else "64"
            result[key] = True
    return result


def extract_compkill_candidates(source_name: str, html: str):
    results = []
    if not html:
        return results

    for m in PATH_RE.finditer(html):
        prefix = m.group(1) or ""
        fname = m.group(2)
        if not prefix:
            continue
        url = normalize_url(prefix + fname)
        p = parse_compkill(fname)
        if not p:
            continue
        x, yyyy = p
        results.append({
            "source": source_name,
            "url": url,
            "x": x,
            "yyyy": yyyy,
            "name": fname,
            "bits": bits_from_x(x),
        })

    for m in BUDATA_RE.finditer(html):
        url = decode_budata(m.group(1))
        if not url:
            continue
        fname_m = re.search(r"/([^/]+\.zip)$", url, re.IGNORECASE)
        if not fname_m:
            continue
        fname = fname_m.group(1)
        p = parse_compkill(fname)
        if not p:
            continue
        x, yyyy = p
        results.append({
            "source": source_name,
            "url": url,
            "x": x,
            "yyyy": yyyy,
            "name": fname,
            "bits": bits_from_x(x),
        })

    return results


def download_one(url: str, out_name: str, local_exists: bool = False) -> bool:
    print(f"\n--- 下载: {out_name}")
    if local_exists:
        print(f"    本地已有旧版压缩包，正在覆盖旧版本 ...")
    else:
        print(f"    本地无此文件，将新增下载 ...")
    print(f"    URL: {url}")
    cmd = [
        ARIA2C_CMD,
        "-x", "16", "-s", "16",
        "--allow-overwrite=true",
        "--auto-file-renaming=false",
        "-d", SCRIPT_DIR,
        "-o", out_name,
        url,
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"    [ok] {out_name}")
        return True
    except Exception as e:
        print(f"    [错误] 下载失败: {e}")
        return False


def run_extract(zip_paths):
    if not zip_paths:
        return
    if not os.path.exists(EXTRACT_BAT):
        print(f"[warn] 未找到 Extract.bat，跳过解压。")
        return
    print(f"\n开始解压 {len(zip_paths)} 个文件 ...")
    for zp in zip_paths:
        print(f"\n--- 解压: {os.path.basename(zp)}")
        try:
            subprocess.run([EXTRACT_BAT, zp], cwd=SCRIPT_DIR, shell=True)
        except Exception as e:
            print(f"    [warn] 调用 Extract.bat 失败: {e}")


# ==========================================
# 主流程
# ==========================================
def main():
    print("=" * 64)
    print("360 系统急救箱 半自动更新")
    print("=" * 64)

    if not os.path.exists(ARIA2C_CMD):
        print(f"[错误] 找不到 aria2: {ARIA2C_CMD}")
        input("按回车键退出...")
        sys.exit(1)

    # ---------- 1. 本地扫描 ----------
    print("\n[1/4] 扫描本地版本...")
    local_ck = scan_local_compkill(SCRIPT_DIR)
    local_wp = scan_local_winpe(SCRIPT_DIR)

    print("  -- 独立版 --")
    for bits in ("32", "64"):
        info = local_ck[bits]
        if info:
            print(f"     独立版 {bits}位: 有  ({info[1]})")
        else:
            print(f"     独立版 {bits}位: 无")

    print("  -- WinPE 版 --")
    for bits in ("32", "64"):
        if local_wp[bits]:
            print(f"     WinPE  {bits}位: 有，正在覆盖旧版本")
        else:
            print(f"     WinPE  {bits}位: 无")

    # ---------- 2. 抓取独立版来源 ----------
    print("\n[2/4] 抓取独立版来源...")
    all_candidates = []
    for src in SOURCES:
        print(f"  -> {src['name']}: {src['url']}")
        html = fetch_html(src["url"])
        cands = extract_compkill_candidates(src["name"], html)
        print(f"     抓到 {len(cands)} 条链接")
        all_candidates.extend(cands)

    uniq = {}
    for c in all_candidates:
        key = c["url"].lower()
        if key not in uniq:
            uniq[key] = dict(c)
            uniq[key]["sources"] = [c["source"]]
        else:
            if c["source"] not in uniq[key]["sources"]:
                uniq[key]["sources"].append(c["source"])
    all_candidates = list(uniq.values())

    # ---------- 3. 版本比对 ----------
    print("\n[3/4] 独立版版本比对...")
    if not all_candidates:
        print("  [warn] 没有抓到任何独立版链接。")
        newer = []
    else:
        newer = []
        for c in all_candidates:
            key = "32" if c["x"] == 0 else ("64" if c["x"] == 64 else None)
            if key is None:
                newer.append(c)
                continue
            old = local_ck[key]
            if old is None or c["yyyy"] > old[0]:
                newer.append(c)

        if not newer:
            print("  没有比本地更新的独立版版本。")
            print("  下面列出所有抓到的版本，仅供手动查看：")
            newer = all_candidates

    def sort_key(c):
        return (-c["yyyy"], 0 if c["bits"] == "64位" else 1, c["name"])

    newer.sort(key=sort_key)

    # ---------- 4. 列表 + 多选 ----------
    print("\n[4/4] 请选择要下载的内容")
    print("-" * 64)

    for i, c in enumerate(newer, 1):
        srcs = "+".join(c.get("sources", [c["source"]]))
        print(f"  [{i:>2}] 独立版 {c['bits']:4s} "
              f"版本:{c['yyyy']:<5d} 来源:{srcs}")
        print(f"       文件: {c['name']}")
        print(f"       URL : {c['url']}")

    winpe_start = len(newer) + 1
    for j, w in enumerate(WINPE_FIXED):
        idx = winpe_start + j
        key = "32" if w["bits"] == "32位" else "64"
        exist_tag = "本地已有，将覆盖" if local_wp[key] else "本地无，将新增"
        print(f"  [{idx:>2}] WinPE  {w['bits']:4s} 固定链接 [{exist_tag}]")
        print(f"       文件: {w['name']}")
        print(f"       URL : {w['url']}")

    print("-" * 64)
    print("输入序号（可多选，如 1,3,5 或 all），多个序号之间用“英文逗号+空格”分隔，直接回车退出。")

    total = len(newer) + len(WINPE_FIXED)

    while True:
        choice = input("\n请选择 > ").strip()
        if choice == "":
            print("已取消，未下载任何文件。")
            break

        if choice.lower() == "all":
            selected = list(range(1, total + 1))
        else:
            selected = []
            ok = True
            for part in choice.split(","):
                part = part.strip()
                if not part:
                    continue
                if not part.isdigit():
                    ok = False
                    break
                idx = int(part)
                if not (1 <= idx <= total):
                    ok = False
                    break
                selected.append(idx)
            if not ok or not selected:
                print(f"[提示] 输入无效，请输入 1~{total} 之间的序号，或 all。")
                continue

        seen = set()
        picked = []
        for idx in selected:
            if idx not in seen:
                seen.add(idx)
                picked.append(idx)

        compkill_picks = [newer[i - 1] for i in picked if i <= len(newer)]
        winpe_picks = [
            WINPE_FIXED[i - winpe_start] for i in picked if i >= winpe_start
        ]

        print("\n开始批量下载 ...")
        downloaded = []

        for c in compkill_picks:
            if download_one(c["url"], c["name"]):
                downloaded.append(os.path.join(SCRIPT_DIR, c["name"]))

        for w in winpe_picks:
            key = "32" if w["bits"] == "32位" else "64"
            if download_one(w["url"], w["name"], local_exists=local_wp[key]):
                downloaded.append(os.path.join(SCRIPT_DIR, w["name"]))

        if not downloaded:
            print("\n[提示] 本次没有成功下载任何文件。")
            print("可以继续选择，或直接回车退出。")
            continue

        run_extract(downloaded)

        print("\n本轮完成。可以继续选择其它版本，或直接回车退出。")

    input("按回车键退出...")


if __name__ == "__main__":
    main()