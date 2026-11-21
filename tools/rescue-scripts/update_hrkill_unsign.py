
import sys
import json
import subprocess
import os
import tempfile
import re
import http.client
import ssl

# ==========================================
# 配置区域
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = SCRIPT_DIR
SETTINGS_PATH = os.path.join(SCRIPT_DIR, "settings.json")
ARIA2C_CMD = os.path.join(SCRIPT_DIR, "aria2-1.37.0-win-64bit-build1", "aria2c.exe")

DEFAULT_FINAL_NAME = "hrkill_unsign.exe"
DEFAULT_URL = "https://down7.huorong.cn/hrkill/hrkill_unsign-1.0.0.193.exe"

# 火绒官方确认存在的 5 个下载/更新服务器
KNOWN_SERVERS = [
    "down3",        # 经测试可靠
    "down7",        # 经测试可靠（默认配置）
    "update",       # 火绒官方更新服务器
    "down2",        # 备用
    "down-tencent", # 腾讯云备用
]

MAX_VERSION_CHECK = 100  # 单次探测最多检查 100 个版本号
MAX_RETRY = 20           # 下载失败最多重试次数


# ---------- 工具函数 ----------
def extract_version(url):
    """从 URL 中提取最后一个数字作为版本号"""
    match = re.search(r'(\d+)\.exe$', url)
    if match:
        return int(match.group(1))
    return None


def extract_server_prefix(url):
    """从 URL 中提取服务器前缀，如 down7"""
    match = re.search(r'https://(down\d+(?:-tencent)?|update)\.huorong\.cn', url)
    if match:
        return match.group(1)
    return None


# ---------- 配置读写 ----------
def load_settings():
    """读取 settings.json，返回 (url, final_name)"""
    if not os.path.exists(SETTINGS_PATH):
        print(f"[警告] 未找到配置文件: {SETTINGS_PATH}，使用内置默认值。")
        return DEFAULT_URL, DEFAULT_FINAL_NAME

    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[错误] 读取 settings.json 失败: {e}，使用内置默认值。")
        return DEFAULT_URL, DEFAULT_FINAL_NAME

    url = (data.get("hrkill_unsign_url") or "").strip() or DEFAULT_URL
    final_name = (data.get("final_name") or DEFAULT_FINAL_NAME).strip() or DEFAULT_FINAL_NAME
    return url, final_name


def save_url_to_settings(new_url):
    """原子地把新 URL 写回 settings.json"""
    data = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

    data["hrkill_unsign_url"] = new_url
    data.setdefault("final_name", DEFAULT_FINAL_NAME)

    dir_name = os.path.dirname(SETTINGS_PATH) or "."
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=".settings_", suffix=".json", dir=dir_name)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, SETTINGS_PATH)
        print(f"[已更新] settings.json 中的 hrkill_unsign_url = {new_url}")
        return True
    except Exception as e:
        print(f"[警告] 写回 settings.json 失败: {e}")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return False


# ---------- 核心探测与下载 ----------
def check_url_head(url, timeout=5):
    """
    使用 http.client 发送 HEAD 请求检查 URL 状态码。
    返回: (is_ok, status_code)
    is_ok=True 表示网络连通（无论 200/404），False 表示网络故障/超时
    """
    try:
        parsed = re.match(r'https?://([^/]+)(/.*)', url)
        if not parsed:
            return False, None
        host = parsed.group(1)
        path = parsed.group(2)

        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=context)
        conn.request("HEAD", path)
        resp = conn.getresponse()
        code = resp.status
        conn.close()
        return True, code
    except Exception:
        return False, None


def get_latest_version(current_url):
    """
    从当前版本号开始递增探测最新版本。
    返回: (latest_url, is_truncated)
    is_truncated=True 表示探测被上限截断，下载的版本可能不是最终最新版
    """
    current_version = extract_version(current_url)
    if not current_version:
        print("[警告] 无法从 URL 解析版本号，跳过自动升级检查。")
        return current_url, False

    print(f"\n[信息] 当前版本号: {current_version}，开始探测最新版本...")

    latest_found_version = current_version  # 保底：至少是当前版本
    is_truncated = False

    # 从下一个版本开始探测
    check_version = current_version + 1

    while check_version < current_version + MAX_VERSION_CHECK:
        found_this_version = False

        # 对每个候选版本号，遍历所有已知服务器
        for server in KNOWN_SERVERS:
            test_url = f"https://{server}.huorong.cn/hrkill/hrkill_unsign-1.0.0.{check_version}.exe"
            is_ok, status_code = check_url_head(test_url, timeout=5)

            if is_ok and status_code == 200:
                latest_found_version = check_version
                found_this_version = True
                break  # 找到就跳出服务器循环，继续探测下一个版本号

        if found_this_version:
            check_version += 1
        else:
            # 所有服务器都返回 404 或不可达，说明当前 latest_found_version 就是最新
            break

    # 判断是否被上限截断
    if check_version >= current_version + MAX_VERSION_CHECK:
        is_truncated = True

    if is_truncated:
        print(f"\n[警告] 探测已达上限（检查了 {MAX_VERSION_CHECK} 个版本），"
              f"就地下载版本 {latest_found_version}。")
        print(f"[提示] 这可能不是最新版，请在本次运行结束后重启脚本进行二次探测。")
    elif latest_found_version == current_version:
        print(f"\n[信息] 未发现新版本，当前版本 {current_version} 已是最新。")
    else:
        print(f"\n[信息] 检测到最新版本: {latest_found_version}")

    # 用当前 settings.json 中的服务器前缀构建最终 URL
    server_prefix = extract_server_prefix(current_url) or "down7"
    final_url = f"https://{server_prefix}.huorong.cn/hrkill/hrkill_unsign-1.0.0.{latest_found_version}.exe"
    return final_url, is_truncated


def download_file(url, target_dir, final_name):
    """使用 aria2 下载。返回 (ok: bool, reason: str)"""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    final_path = os.path.join(target_dir, final_name)

    cmd = [
        ARIA2C_CMD,
        "-x", "16", "-s", "16",
        "--allow-overwrite=true",
        "--auto-file-renaming=false",
        "-d", target_dir,
        "-o", final_name,
        "--connect-timeout=10",
        url
    ]

    print(f"\n正在下载并覆盖: {final_path}")
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        return False, f"aria2 返回码 {e.returncode}"
    except Exception as e:
        return False, f"启动 aria2 失败: {e}"

    if not os.path.exists(final_path):
        return False, "下载完成但目标文件不存在"

    size = os.path.getsize(final_path)
    if size < 100 * 1024:
        return False, f"下载文件过小({size} 字节)，可能不是有效程序"

    print("\n下载任务已完成！")
    return True, ""


def get_priority_server_urls(current_url):
    """
    生成带优先级的服务器 URL 列表。
    当前配置的服务器永远排第一，其余按 KNOWN_SERVERS 顺序排列。
    """
    current_server = extract_server_prefix(current_url)
    version = extract_version(current_url)
    if not version:
        return [current_url]

    ordered_servers = []
    # 当前服务器排第一
    if current_server:
        ordered_servers.append(current_server)
    # 其余已知服务器按顺序补充
    for s in KNOWN_SERVERS:
        if s != current_server:
            ordered_servers.append(s)

    urls = []
    for s in ordered_servers:
        urls.append(f"https://{s}.huorong.cn/hrkill/hrkill_unsign-1.0.0.{version}.exe")
    return urls


def try_download_with_fallback(url, target_dir, final_name):
    """
    包含 CDN 自动切换逻辑的下载函数。
    返回: (ok: bool, final_url: str)
    """
    candidate_urls = get_priority_server_urls(url)

    for candidate_url in candidate_urls:
        server_name = extract_server_prefix(candidate_url) or "unknown"
        print(f"正在尝试从 {server_name} 下载...")
        ok, reason = download_file(candidate_url, target_dir, final_name)
        if ok:
            return True, candidate_url
        else:
            print(f"[失败] {server_name}: {reason}")

    return False, url


# ---------- 交互与主流程 ----------
def ask_and_update_url():
    """询问用户新链接，返回是否成功写回"""
    print("\n[错误] 所有 CDN 节点均无法下载，请输入正确的下载链接")
    print("（直接回车表示放弃本次更新）")
    try:
        new_url = input("新链接: ").strip()
    except EOFError:
        return False

    if not new_url:
        return False

    if not (new_url.startswith("http://") or new_url.startswith("https://")):
        print("[警告] 链接似乎不是以 http:// 或 https:// 开头，仍会尝试写入并下载。")

    return save_url_to_settings(new_url)


def main():
    print("=" * 50)
    print("火绒恶性木马专杀工具（无签名版）自动更新脚本")
    print("=" * 50)

    url, final_name = load_settings()

    # === 第一步：版本自动探测（带保底机制）===
    latest_url, is_truncated = get_latest_version(url)

    for attempt in range(1, MAX_RETRY + 1):
        print(f"\n--- 第 {attempt} 次尝试 ---")
        print(f"目标链接: {latest_url}")
        print(f"保存文件名: {final_name}")

        # === 第二步：带 CDN 切换的下载 ===
        ok, final_url = try_download_with_fallback(latest_url, TARGET_DIR, final_name)

        if ok:
            # 下载成功，如果是从别的 CDN 下的，自动更新 settings
            if final_url != url:
                save_url_to_settings(final_url)
            break

        # 下载彻底失败
        if attempt >= MAX_RETRY:
            print(f"\n[错误] 已重试 {MAX_RETRY} 次，放弃。")
            input("按回车键退出...")
            sys.exit(1)

        if not ask_and_update_url():
            print("\n已放弃本次更新。")
            input("按回车键退出...")
            sys.exit(1)

        # 用户输入了新 URL，重新加载并循环
        url, final_name = load_settings()
        latest_url = url

    # ---------- 下载成功，询问是否运行 ----------
    url, final_name = load_settings()
    exe_path = os.path.join(TARGET_DIR, final_name)

    print("\n" + "=" * 40)
    while True:
        user_input = input(
            "请确认 内核隔离 已关闭。是否立即运行 火绒恶性木马专杀工具（无签名版）? (Y/N): "
        ).strip()
        if user_input.lower() == 'y':
            print("\n正在启动 火绒恶性木马专杀工具（无签名版）...")
            try:
                subprocess.Popen([exe_path], shell=True)
                print("程序已启动！")
            except Exception as e:
                print(f"启动失败: {e}")
            break
        elif user_input.lower() == 'n':
            break
        else:
            print("无效输入，请输入 Y 或 N。")

    print("\n按回车键退出...")
    input()


if __name__ == "__main__":
    main()
