#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import shutil
import sys
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures

def sanitize_openvpn_config(text: str) -> str:
    """
    [安全核心] 清洗 OpenVPN 配置文件，剔除所有可能导致 RCE (远程代码执行) 的危险指令
    """
    safe_lines = []
    # OpenVPN 中可能被滥用执行本地命令的危险指令集
    dangerous_cmds = {
        "up", "down", "route-up", "route-pre-down", "ipchange",
        "script-security", "plugin", "tls-verify", 
        "auth-user-pass-verify", "client-connect", "client-disconnect",
        "learn-address"
    }
    
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts or parts[0].startswith(("#", ";")):
            safe_lines.append(line)
            continue
        
        cmd = parts[0].lower()
        if cmd in dangerous_cmds:
            print(f"[安全拦截] 发现并剔除恶意 OpenVPN 指令: {line}", flush=True)
            continue # 丢弃恶意配置行
            
        safe_lines.append(line)
        
    return "\n".join(safe_lines)


# 优先 IPv4 解析避免卡顿
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results: return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                try: self.socket.close()
                except Exception: pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try: self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError: pass
        super().server_bind()

import vpn_utils
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "1260"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "1260"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "300"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "52928"))
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = int(os.environ.get("UI_PORT", "18658"))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"

lock = threading.RLock()
active_sessions: dict[str, dict[str, Any]] = {}
failed_logins: dict[str, dict[str, Any]] = {} # [新增] 用于记录登录失败状态的内存池
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0

_enrich_lock = threading.Lock()
_last_enrich_time = 0.0

def safe_enrich_ip_info(nodes: list[dict[str, Any]]) -> None:
    global _last_enrich_time
    if not nodes: return
    with _enrich_lock:
        now = time.time()
        elapsed = now - _last_enrich_time
        if elapsed < 4.1:
            time.sleep(4.1 - elapsed)
        try:
            vpn_utils.enrich_ip_info(nodes)
        except Exception as e:
            print(f"[API 风控防范] 忽略该次 IP 属性检测报错: {e}", flush=True)
        _last_enrich_time = time.time()

def cleanup_memory_pools():
    now = time.time()
    with lock:
        # 清理过期 Session
        expired_tokens = [k for k, v in active_sessions.items() if v["expires"] < now]
        for k in expired_tokens:
            del active_sessions[k]
        
        # 清理已过锁定期的失败记录
        expired_locks = [k for k, v in failed_logins.items() if v["lock_until"] > 0 and now >= v["lock_until"]]
        for k in expired_locks:
            del failed_logins[k]

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try: AUTH_FILE.chmod(0o600)
        except OSError: pass

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try: return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): return default

import random

def generate_random_password() -> str:
    import string
    import random
    
    # 明确定义四种字符集
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&+-/*" # 这里明确列出你想要的特殊字符
    
    # 强制每种类型至少选一个，保证绝对安全
    password = [
        random.choice(lower),
        random.choice(upper),
        random.choice(digits),
        random.choice(special)
    ]
    
    # 补齐剩下的 8 位 (总共 12 位)
    all_chars = lower + upper + digits + special
    password += random.choices(all_chars, k=16)
    
    # 打乱顺序，防止密码前四位规律性太强
    random.shuffle(password)
    
    return "".join(password)

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        if uname[0].isalpha() and any(c.islower() for c in uname) and any(c.isupper() for c in uname) and any(c.isdigit() for c in uname):
            return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "", "secret_path": "EJsW2EepxyBo9lY", "password": "", "host": "::", "port": 18658,
            "routing_mode": "auto", "force_country": "", "routing_ip_type": "all", "connection_enabled": True, "fixed_node_id": "",
            "bound_domain": "", "ignore_domain_warning": False # 新增这两项域名绑定设置
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items(): config[key] = val
            except Exception: pass
        
        if not config.get("username"): config["username"] = generate_random_username(); updated = True
        if not config.get("password"): config["password"] = generate_random_password(); updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                # 原子化安全写入：文件落地瞬间即为 0600，无需事后再 chmod，避免了 try 嵌套的混乱
                content = json.dumps(config, ensure_ascii=False, indent=2).encode("utf-8")
                fd = os.open(str(auth_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with open(fd, 'wb') as f:
                    f.write(content)
            except Exception: 
                pass
        return config

try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg: LOCAL_PROXY_PORT = int(_init_cfg["proxy_port"])
    if "port" in _init_cfg: UI_PORT = int(_init_cfg["port"])
    if "host" in _init_cfg: UI_HOST = _init_cfg["host"]
except Exception: pass

# === 新增：高频易失性内存池 ===
_mem_state: dict[str, Any] = {}
# 只有这些高频变动且重启后不需要保存的状态，才会被拦截在内存中
_EPHEMERAL_KEYS = {"active_node_latency", "last_check_message", "proxy_ok", "proxy_ip", "proxy_latency_ms", "proxy_error"}

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    # 获取时，将硬盘数据与内存最新数据动态合并返回给前端
    state.update(_mem_state) 
    
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 18658)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EepxyBo9lY")
    state["proxy_port"] = ui_cfg.get("proxy_port", 52928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["bound_domain"] = ui_cfg.get("bound_domain", "")
    state["ignore_domain_warning"] = ui_cfg.get("ignore_domain_warning", False)
    
    state["singbox_enabled"] = Path("/etc/sing-box/config.json.bak").exists()
    return state

def set_state(**updates: Any) -> None:
    disk_updates = {}
    for k, v in updates.items():
        if k in _EPHEMERAL_KEYS:
            _mem_state[k] = v  # 拦截高频写入，仅存内存
        else:
            disk_updates[k] = v # 真正需要持久化的配置
            
    if disk_updates:
        # 只有在需要写入硬盘时才发起 IO 请求
        state = read_json(STATE_FILE, {})
        state.update(disk_updates)
        write_json(STATE_FILE, state)

def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("._") or "node"

def parse_int(value: Any) -> int:
    try: return int(value)
    except (TypeError, ValueError): return 0

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None: url = API_URL
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0", "Accept": "text/plain,*/*"})
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    # --- [安全修复] 洗刷包含恶意脚本的配置 ---
    config_text = sanitize_openvpn_config(config_text)
    # --------------------------------------
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id, "country": country_zh, "country_short": country_short, "ip": ip,
        "score": parse_int(row.get("Score")), "ping": parse_int(row.get("Ping")), "speed": parse_int(row.get("Speed")),
        "owner": "", "asn": "", "as_name": "", "location": "", "ip_type": "", "quality": "",
        "latency_ms": 0, "config_file": str(config_path), "config_text": config_text,
        "proto": proto, "remote_host": remote_host, "remote_port": remote_port,
        "probe_status": "not_checked", "probe_message": "",
    }

def fetch_candidates() -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    # [安全修复] 删除 (API_URL, False) 回退，强制校验 SSL 证书，防止中间人投毒
    for url, verify_ssl in [(API_URL, True)]:
        for _ in range(2):
            try:
                api_text = fetch_api_text(url, verify_ssl)
                for row in parse_vpngate_rows(api_text)[:MAX_SCAN_ROWS]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips: continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded: continue
                    candidates.append(row_to_node(row, decode_config(encoded)))
                    seen_ips.add(ip)
                if candidates: break
            except Exception: time.sleep(1.5)
        if candidates: break
    if not candidates: raise RuntimeError("Failed to fetch API")
    set_state(last_fetch_at=time.time())
    return candidates

def get_openvpn_version() -> float:
    try:
        res = subprocess.run(["openvpn", "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match: return float(match.group(1))
    except Exception: pass
    return 2.4

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    cmd = ["openvpn", "--config", config_file, "--dev", dev, "--dev-type", "tun", "--pull-filter", "ignore", "route-ipv6",
           "--pull-filter", "ignore", "ifconfig-ipv6", "--route-delay", "2", "--connect-retry-max", "1",
           "--connect-timeout", "15", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--verb", "3",
           "--script-security", "1"] # <--- [安全修复] 强制锁定安全级别，禁止执行外部命令]
    if get_openvpn_version() >= 2.5: cmd.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else: cmd.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    if route_nopull: cmd.append("--route-nopull")
    return cmd

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None: return
    process.terminate()
    try: process.wait(timeout=3)
    except subprocess.TimeoutExpired: process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"): return
    try:
        subprocess.run(["pkill", "-f", "openvpn.*tun0"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "openvpn.*vpngate_data"], capture_output=True, timeout=2)
    except Exception: pass

def update_handshake_status(line_lower: str) -> None:
    status_map = {"resolving": ("解析域名", "解析IP..."), "udp link local": ("物理连接", "发送数据包..."),
                  "tls: initial packet": ("证书握手", "建立TLS..."), "verify ok": ("证书校验", "验证身份..."),
                  "peer connection initiated": ("协商加密", "初始化加密..."), "push_request": ("请求配置", "请求IP..."),
                  "push_reply": ("应用配置", "获取IP..."), "tun/tap device": ("创建网卡", "创建TUN..."),}
    for key, (short, desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short, last_check_message=desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(openvpn_command(config_file, route_nopull, dev), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", cwd=str(ROOT_DIR))
    except Exception as exc: return False, f"Failed: {exc}", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        for line in process.stdout:
            if not startup_done[0]: lines.put(line.rstrip())
        if not startup_done[0]: lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time(); ok = False; message = "Timeout"; tail = []
    while time.time() - started < limit:
        try: line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None: break
            continue
        if line is None: break
        if line: tail.append(line); tail = tail[-8:]
        if keep_alive: update_handshake_status(line.lower())
        if "initialization sequence completed" in line.lower():
            ok = True; message = f"Connected in {int((time.time() - started) * 1000)} ms."; break
        if "auth_failed" in line.lower() or "fatal error" in line.lower() or "cannot ioctl" in line.lower():
            message = line[-100:]; break
    
    startup_done[0] = True
    if not ok or not keep_alive: stop_process(process); process = None
    return ok, message, process

def setup_policy_routing(interface: str = "tun0") -> None:
    try: subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception: pass
    try: subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception: pass
    try:
        subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
        subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
        for p in ["all", "default", interface]:
            try: subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{p}.rp_filter=2"], capture_output=True, timeout=2)
            except Exception: pass
    except Exception: pass

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception: pass

def toggle_singbox(enable: bool, proxy_port: int) -> tuple[bool, str]:
    sb_conf = Path("/etc/sing-box/config.json")
    sb_bak = Path("/etc/sing-box/config.json.bak")
    if not sb_conf.exists() and not sb_bak.exists(): return False, "未找到 Sing-box 配置文件"
    try:
        if enable:
            if not sb_bak.exists(): shutil.copy(sb_conf, sb_bak)
            data = json.loads(sb_conf.read_text(encoding="utf-8"))
            outbounds = [ob for ob in data.get("outbounds", []) if ob.get("tag") != "aimilivpn_socks"]
            outbounds.insert(0, {"type": "socks", "tag": "aimilivpn_socks", "server": "127.0.0.1", "server_port": proxy_port})
            data["outbounds"] = outbounds
            route = data.get("route", {})
            rules = [r for r in route.get("rules", []) if r.get("outbound") != "aimilivpn_socks"]
            rules.insert(0, {"outbound": "aimilivpn_socks"})
            route["rules"] = rules
            data["route"] = route
            sb_conf.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            if sb_bak.exists(): 
                shutil.copy(sb_bak, sb_conf)
                sb_bak.unlink()
        subprocess.run(["systemctl", "restart", "sing-box"], check=True, capture_output=True)
        return True, "Sing-box 出站接管已" + ("启用" if enable else "关闭")
    except Exception as e: return False, f"操作失败: {e}"

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_json(NODES_FILE, [])
            n = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if n: config_to_delete = n.get("config_file")
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()
        if config_to_delete:
            try: Path(config_to_delete).unlink()
            except Exception: pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(nodes, key=lambda n: (
        0 if n.get("probe_status") == "available" or n.get("active") else (1 if n.get("probe_status") == "not_checked" else 2),
        0 if n.get("ip_type") in ("residential", "mobile") else 1,
        parse_int(n.get("latency_ms")) or 999999,
        -parse_int(n.get("score"))
    ))

active_test_indexes = set()
test_indexes_lock = threading.Lock()
def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx); return idx
        return 99
def release_test_index(idx: int) -> None:
    with test_indexes_lock: active_test_indexes.discard(idx)

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node: raise ValueError("Node not found")
        cfg_file = str(node["config_file"]); cfg_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip")); p = parse_int(node.get("remote_port"))

    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        Path(cfg_file).write_text(cfg_text, encoding="utf-8")
    except Exception: return {}

    latency = vpn_utils.ping_latency_ms(h, p, parse_int(node.get("ping")))
    idx = get_free_test_index()
    try: ok, message, _ = run_openvpn_until_ready(cfg_file, keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
    finally:
        release_test_index(idx)
        try: Path(cfg_file).unlink()
        except Exception: pass

    temp_node = {
        "id": node_id, "ip": h, "remote_host": h, "remote_port": p,
        "owner": node.get("owner", ""), "asn": node.get("asn", ""), "as_name": node.get("as_name", ""),
        "location": node.get("location", ""), "ip_type": node.get("ip_type", ""), "quality": node.get("quality", "")
    }
    
    if ok: safe_enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            if ok:
                node["owner"] = temp_node.get("owner", "")
                node["asn"] = temp_node.get("asn", "")
                node["as_name"] = temp_node.get("as_name", "")
                node["location"] = temp_node.get("location", "")
                node["ip_type"] = temp_node.get("ip_type", "")
                node["quality"] = temp_node.get("quality", "")
            write_json(NODES_FILE, sort_all_nodes(nodes))
            return next((item for item in nodes if item.get("id") == node_id), node)
        return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock: to_test = [n for n in read_json(NODES_FILE, []) if n.get("id") in node_ids]
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        nid = n_info["id"]; cfg_file = n_info["config_file"]; h = str(n_info.get("remote_host") or n_info.get("ip")); p = parse_int(n_info.get("remote_port"))
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            Path(cfg_file).write_text(n_info.get("config_text") or "", encoding="utf-8")
        except Exception: return {"id": nid, "probe_status": "unavailable", "latency_ms": 0}
        
        latency = vpn_utils.ping_latency_ms(h, p, parse_int(n_info.get("ping")))
        t_idx = get_free_test_index()
        try: ok, msg, _ = run_openvpn_until_ready(cfg_file, keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{t_idx}")
        finally:
            release_test_index(t_idx)
            try: Path(cfg_file).unlink()
            except Exception: pass
            
        return {
            "id": nid, "latency_ms": latency, "probe_status": "available" if ok else "unavailable", "probe_message": msg,
            "ip": h, "remote_host": h, "remote_port": p,
            "owner": n_info.get("owner", ""), "asn": n_info.get("asn", ""), "as_name": n_info.get("as_name", ""),
            "location": n_info.get("location", ""), "ip_type": n_info.get("ip_type", ""), "quality": n_info.get("quality", "")
        }

    updated = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(15, max(1, len(to_test)))) as executor:
        futs = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for fut in concurrent.futures.as_completed(futs):
            nid = futs[fut]
            try: updated[nid] = fut.result()
            except Exception: updated[nid] = {"id": nid, "probe_status": "unavailable", "latency_ms": 0}

    succ = [r for r in updated.values() if r.get("probe_status") == "available"]
    if succ:
        try: safe_enrich_ip_info(succ)
        except Exception: pass

    with lock:
        nodes = read_json(NODES_FILE, [])
        for n in nodes:
            if n.get("id") in updated: n.update(updated[n["id"]])
        write_json(NODES_FILE, sort_all_nodes(nodes))
    return list(updated.values())

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3: return
    ui_cfg = load_ui_config()
    if not ui_cfg.get("connection_enabled", True) or ui_cfg.get("routing_mode", "auto") == "fixed_ip": return

    with lock:
        nodes = read_json(NODES_FILE, [])
        a_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
        active_country = a_node.get("country", "") if a_node else ""
        
        candidates = [n for n in nodes if n.get("probe_status") == "available" and not n.get("active")]
        
        if ui_cfg.get("routing_mode") == "fixed_region" and ui_cfg.get("force_country", ""):
            candidates = [n for n in candidates if n.get("country") == ui_cfg.get("force_country", "")]
        elif active_country and ui_cfg.get("routing_mode") != "fixed_region":
            same_cands = [n for n in candidates if n.get("country") == active_country]
            if same_cands: candidates = same_cands
            
        routing_ip_type = ui_cfg.get("routing_ip_type", "all")
        if routing_ip_type == "residential":
            candidates = [n for n in candidates if n.get("ip_type") in ("residential", "mobile")]
        elif routing_ip_type == "hosting":
            candidates = [n for n in candidates if n.get("ip_type") == "hosting"]
            
        candidates.sort(key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        ))
        
    if candidates:
        try: connect_node(candidates[0]["id"])
        except Exception: auto_switch_node(attempt + 1)
    else:
        stop_active_openvpn()
        with lock:
            nodes = read_json(NODES_FILE, [])
            for item in nodes: item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message="备选池空竭，后台获取中...", connected_at=0)
        threading.Thread(target=lambda: maintain_valid_nodes(force=False) or auto_switch_node(), daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    with lock:
        if is_connecting: return "Already connecting"
        is_connecting = True
        active_openvpn_node_id = node_id
        set_state(active_openvpn_node_id=node_id, is_connecting=True, active_node_latency="正在连接", last_check_message="初始化配置...")
        
    try:
        ui_cfg = load_ui_config(); ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip": ui_cfg["fixed_node_id"] = node_id
        with lock: (DATA_DIR / "ui_auth.json").write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
            
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node: raise ValueError("Node not found")
        
        stop_active_openvpn()
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e: raise RuntimeError(f"Config err: {e}")

        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try: config_path.unlink()
            except Exception: pass
            node["probe_status"] = "unavailable"; node["probe_message"] = message
            for item in nodes: item["active"] = False
            write_json(NODES_FILE, nodes)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", connected_at=0)
            with lock: active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        with lock:
            active_openvpn_process = process; active_openvpn_node_id = node_id
        
        setup_policy_routing("tun0")
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time(); last_active_latency = 0
        try:
            lat = vpn_utils.ping_latency_ms(node.get("ip") or node.get("remote_host"), parse_int(node.get("remote_port")), parse_int(node.get("ping")))
            if lat > 0: last_active_latency = lat
        except Exception: pass
            
        for item in nodes: item["active"] = (item.get("id") == node_id)
        write_json(NODES_FILE, nodes)
        
        res = check_proxy_health()
        if res["ok"]: set_state(proxy_ok=True, proxy_ip=res["ip"], proxy_latency_ms=res["latency_ms"], proxy_error="")
        else: set_state(proxy_ok=False, proxy_ip="-", proxy_latency_ms=0, proxy_error=res.get("error", ""))
            
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message="连接成功", active_node_latency=f"{last_active_latency} ms" if last_active_latency > 0 else "已连接", connected_at=time.time())
        return f"Connected {node_id}"
    finally:
        with lock: is_connecting = False

def maintain_valid_nodes(force: bool = False) -> str:
    global is_connecting
    ensure_dirs()
    is_connecting = True
    try:
        if force:
            with lock: stop_active_openvpn()
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            if ui_cfg.get("connection_enabled", True):
                if ui_cfg.get("routing_mode", "auto") == "fixed_ip" and active_openvpn_node_id:
                    is_connecting = False
                    try: connect_node(active_openvpn_node_id)
                    except Exception: pass
                    is_connecting = True
                else:
                    has_active = False
                    with lock:
                        if active_openvpn_node_id: has_active = True; stop_active_openvpn()
                    if has_active:
                        is_connecting = False; auto_switch_node(); is_connecting = True

        try:
            last_fetch_at = get_state().get("last_fetch_at", 0)
            current_nodes_count = len(read_json(NODES_FILE, []))
            if force or time.time() - last_fetch_at > FETCH_INTERVAL_SECONDS or current_nodes_count < 20:
                candidates = fetch_candidates()
            else:
                candidates = []
        except Exception: candidates = []

        with lock:
            active_node = next((n for n in read_json(NODES_FILE, []) if n.get("id") == active_openvpn_node_id), None)
            merged = [active_node] if active_node else []
            seen = {n["id"] for n in merged}
            if candidates:
                for cand in candidates:
                    if cand["id"] not in seen: merged.append(cand); seen.add(cand["id"])
                merged = merged[:1000]
                for n in merged:
                    p = Path(n["config_file"])
                    if not p.exists():
                        try: p.write_text(n["config_text"], encoding="utf-8")
                        except Exception: pass
                write_json(NODES_FILE, merged)

        with lock:
            current_nodes = read_json(NODES_FILE, [])
            to_test = [n for n in current_nodes if not n.get("active") and n.get("probe_status") == "not_checked"]
            to_test_ids = [n["id"] for n in to_test]
            
        if to_test_ids: 
            print(f"[维护线程] 正在并发检测未检测节点，共 {len(to_test_ids)} 个...", flush=True)
            test_multiple_nodes(to_test_ids)
            
        is_connecting = False
        
        with lock:
            if not active_openvpn_running() and load_ui_config().get("connection_enabled", True) and load_ui_config().get("routing_mode", "auto") != "fixed_ip":
                auto_switch_node()
        return "Fetch completed"
    except Exception as e:
        is_connecting = False
        raise e

def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            if "没有拉取到新节点" not in maintain_valid_nodes(force=False): success = True
        except Exception: pass
        time.sleep(120 if not active_openvpn_running() and not success else CHECK_INTERVAL_SECONDS)

def daily_scheduler_loop() -> None:
    while True:
        try:
            now = time.localtime()
            future_time = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 7, 0, 0, 0, 0, -1))
            if future_time <= time.time():
                future_time += 86400  
            
            sleep_sec = future_time - time.time()
            time.sleep(sleep_sec)
            
            print("[定时任务] 触发每日 07:00 自动更新节点，清理并拉取最新数据...", flush=True)
            with lock:
                nodes = read_json(NODES_FILE, [])
                fresh_nodes = [n for n in nodes if n.get("active") or n.get("probe_status") == "available"]
                write_json(NODES_FILE, fresh_nodes)
            maintain_valid_nodes(force=True)
            print("[定时任务] 每日 07:00 更新完成！", flush=True)
            
        except Exception as e:
            print(f"[定时任务] 自动更新失败: {e}", flush=True)
            time.sleep(60) 

LOGIN_HTML = r"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>AimiliVPN - 安全登录</title><link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600&display=swap" rel="stylesheet"><style>:root{--bg-dark:#090d16;--bg-surface:rgba(15,23,42,0.45);--text-primary:#f8fafc;--primary:#6366f1;--primary-gradient:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);--danger:#f43f5e;}body{margin:0;font-family:'Outfit',sans-serif;background-color:var(--bg-dark);height:100vh;display:flex;align-items:center;justify-content:center;}.card{background:var(--bg-surface);border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:40px;width:320px;text-align:center;box-shadow:0 20px 40px rgba(0,0,0,0.3);}.card h2{color:var(--text-primary);margin-top:0;}input{width:100%;height:45px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:0 15px;color:#fff;box-sizing:border-box;margin-bottom:15px;outline:none; transition: all 0.3s;}input:focus{border-color:var(--primary);} /* 修复浏览器自动填充导致的白色背景 */ input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus, input:-webkit-autofill:active { -webkit-box-shadow: 0 0 0 30px #1e293b inset !important; -webkit-text-fill-color: #f8fafc !important; transition: background-color 5000s ease-in-out 0s; caret-color: white; } button{width:100%;height:45px;background:var(--primary-gradient);border:none;border-radius:10px;color:#fff;font-weight:600;cursor:pointer;}.err{color:var(--danger);font-size:13px;display:none;margin-bottom:10px;}</style></head><body><div class="card"><h2>AimiliVPN</h2><form onsubmit="handle(event)"><input type="text" id="u" placeholder="管理账号" required><input type="password" id="p" placeholder="安全密码" required><div id="e" class="err"></div><button type="submit" id="b">登录</button></form></div><script>async function handle(e){e.preventDefault();$("e").style.display="none";$("b").innerText="验证...";try{const r=await fetch("./api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("u").value,password:$("p").value})});const d=await r.json();if(d.ok){$("b").innerText="登录成功，正在跳转...";setTimeout(()=>window.location.reload(),300);}else{$("e").innerText=d.error;$("e").style.display="block";$("b").innerText="登录";}}catch(e){$("e").innerText="网络错误";$("e").style.display="block";$("b").innerText="登录";}}const $=id=>document.getElementById(id);</script></body></html>"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AimiliVPN 节点管理</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap');
    :root {
      --bg-dark: #0b0f19; --bg-surface: rgba(22, 30, 49, 0.6); --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f3f4f6; --text-secondary: #9ca3af;
      --primary: #6366f1; --success: #10b981; --danger: #f43f5e; --warning: #f59e0b;
      --active-row-bg: rgba(16, 185, 129, 0.06);
    }
    body { margin: 0; font-family: 'Outfit', sans-serif; background-color: var(--bg-dark); color: var(--text-primary); min-height: 100vh; }
    header { padding: 16px 32px; background: rgba(11, 15, 25, 0.7); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
    h1 { font-size: 20px; font-weight: 700; margin: 0; color: #a5b4fc; }
    .btn-group { display: flex; gap: 12px; align-items: center; }
    button, select, input { height: 38px; border: 1px solid var(--border-color); border-radius: 8px; padding: 0 16px; font-weight: 600; cursor: pointer; background: rgba(255, 255, 255, 0.04); color: var(--text-primary); }
    button:hover { background: rgba(255, 255, 255, 0.08); }
    .btn-primary { background: linear-gradient(135deg, #6366f1, #4f46e5); border: none; color: white; }
    select { background-color: var(--bg-surface); color: var(--text-primary); }
    select option { background-color: #1e293b; color: #f8fafc; }
    
    main { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }
    .active-card { background: linear-gradient(135deg, rgba(99,102,241,0.12), rgba(79,70,229,0.04)); border: 1px solid rgba(99,102,241,0.25); border-radius: 16px; padding: 24px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
    .toolbar { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px; margin-bottom: 24px; display: flex; gap: 16px; align-items: center; }
    
    .table-container { max-height: 650px; overflow-y: auto; background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 16px; }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th, td { padding: 14px 20px; border-bottom: 1px solid var(--border-color); font-size: 14px; }
    th { position: sticky; top: 0; z-index: 10; background: rgba(17, 24, 39, 0.95); font-size: 12px; color: var(--text-secondary); text-transform: uppercase; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .active-row { background: var(--active-row-bg) !important; outline: 2px solid var(--success) !important; outline-offset: -2px; }
    
    .badge { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; }
    .available { background: rgba(16,185,129,0.1); color: #34d399; }
    .unavailable { background: rgba(244,63,94,0.1); color: #fb7185; }
    .not_checked { background: rgba(245,158,11,0.1); color: #fbbf24; }
    .mono { font-family: 'JetBrains Mono', monospace; color: #a5b4fc; }

    .dropdown { position: relative; display: inline-block; }
    .dropdown-content { display: none; position: absolute; right: 0; margin-top: 6px; min-width: 160px; background: rgba(22, 30, 49, 0.95); border: 1px solid var(--border-color); border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); z-index: 1000; overflow: hidden; }
    .dropdown-content a { display: block; padding: 10px 16px; color: var(--text-primary); text-decoration: none; font-size: 13px; font-weight: 500; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .dropdown-content a:hover { background: rgba(255,255,255,0.08); }
    
    .modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(9, 13, 22, 0.7); backdrop-filter: blur(8px); align-items: center; justify-content: center; }
    .modal-content { background: rgba(22, 30, 49, 0.95); border: 1px solid var(--border-color); border-radius: 16px; width: 90%; max-width: 450px; padding: 24px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
    .form-group input, .form-group select { width: 100%; box-sizing: border-box; }
    
  </style>
</head>
<body>
<header>
  <h1 style="margin: 0;"><a href="https://github.com/HayUnow/aimili-vpngate" target="_blank" style="color: #a5b4fc; text-decoration: none;">AimiliVPN 节点管理</a></h1>
  <div class="btn-group">
    <button id="singbox_btn" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);" onclick="toggleSingbox()">接管 Sing-box</button>
    <button id="refresh" class="btn-primary" onclick="refreshNodes()">更新节点</button>
    
    <div class="dropdown">
      <button id="admin_btn" style="background: rgba(255,255,255,0.08);">管理员设置 ▼</button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openModal('credentials_modal')">账号密码设置</a>
        <a href="javascript:void(0)" onclick="openModal('domain_modal')">绑定域名设置 (安全)</a>
        <a href="javascript:void(0)" onclick="openModal('network_modal')">代理与网络设置</a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger);">退出登录</a>
      </div>
    </div>
  </div>
</header>
<main>
  <div id="active_node_card"></div>
  <section class="toolbar">
    <select id="country_filter"><option value="">所有国家</option></select>
    <select id="ip_type_filter">
      <option value="residential" selected>静态住宅 (推荐)</option>
      <option value="">所有IP类型</option>
      <option value="proxy">代理 IP</option>
      <option value="hosting">机房 IP</option>
    </select>
    <button id="btn_batch_test" class="btn-primary" style="height: 40px; padding: 0 20px;" onclick="batchTestNodes()">批量测试本页延迟</button>
  </section>
  <div class="table-container">
    <table>
      <thead>
        <tr><th>状态</th><th>延迟</th><th>IP地址:端口</th><th>国家地区</th><th>质量 / ISP</th><th>IP 类型</th><th>操作</th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</main>
<div id="domain_modal" class="modal">
  <div class="modal-content">
    <h3>绑定域名 (防 IP 扫描)</h3>
    <p style="font-size:13px; color:var(--text-secondary);">绑定域名后，系统将强制校验，彻底禁止通过 IP 访问面板。</p>
    <div class="form-group">
        <label>您的域名 (例如: vpn.example.com)</label>
        <input type="text" id="bind_domain_input" placeholder="留空则不限制 (允许 IP 访问)">
    </div>
    <div style="text-align: right;">
        <button onclick="closeModal('domain_modal')">取消</button> 
        <button class="btn-primary" onclick="saveDomain()">保存</button>
    </div>
  </div>
</div>

<div id="restart_modal" class="modal" style="display:none; align-items:center; justify-content:center;">
  <div class="modal-content" style="text-align:center; max-width:300px;">
    <h3 style="margin-top:0;">系统重启中</h3>
    <p style="font-size:14px; color:var(--text-secondary);">域名已变更，正在应用 HTTPS 配置...</p>
    <div style="font-size:32px; font-weight:bold; color:var(--primary); margin:20px 0;" id="countdown_num">10</div>
    <p style="font-size:12px; color:var(--text-secondary);">倒计时结束后将自动重定向</p>
  </div>
</div>

<div id="domain_warning_modal" class="modal">
  <div class="modal-content">
    <h3 style="color: var(--warning);">⚠️ 强烈建议：绑定域名</h3>
    <p style="font-size:15px; color:red; line-height: 1.6;font-weight: bold;">
      系统检测到您当前允许通过 IP 直接访问面板，这极易受到网络上的自动扫描程序探测。<br>为了您的数据安全，强烈建议立即绑定域名启用HTTPS访问！
    </p>
    <div style="margin: 16px 0;">
      <label style="font-size: 13px; display: flex; align-items: center; gap: 8px; cursor: pointer;">
        <input type="checkbox" id="chk_ignore_warning"> 忽略此安全警告，不再提示
      </label>
    </div>
    <div style="text-align: right;">
      <button onclick="closeWarningModal()">关闭</button> 
      <button class="btn-primary" onclick="closeModal('domain_warning_modal'); openModal('domain_modal');">前往配置</button>
    </div>
  </div>
</div>
<div id="credentials_modal" class="modal">
  <div class="modal-content">
    <h3>修改管理账号密码</h3>
    <div class="form-group"><label>新管理账号</label><input type="text" id="cred_u"></div>
    <div class="form-group"><label>新安全密码</label><input type="password" id="cred_p"></div>
    <div style="text-align: right;"><button onclick="closeModal('credentials_modal')">取消</button> <button class="btn-primary" onclick="saveCreds()">保存</button></div>
  </div>
</div>

<div id="network_modal" class="modal">
  <div class="modal-content">
    <h3>代理与网络设置</h3>
    <div class="form-group"><label>网页管理端口</label><input type="number" id="net_port"></div>
    <div class="form-group"><label>登录安全后缀</label><input type="text" id="net_suffix"></div>
    <div class="form-group"><label>本地出站代理端口</label><input type="number" id="net_proxy"></div>
    <div class="form-group"><label>IP 路由模式</label>
      <select id="net_routing_mode">
        <option value="auto">自动配置 (智能切换最佳IP)</option>
        <option value="fixed_ip">固定 IP (永不自动换 IP)</option>
      </select>
    </div>
    <div style="text-align: right;"><button onclick="closeModal('network_modal')">取消</button> <button class="btn-primary" onclick="saveNetwork()">保存重启</button></div>
  </div>
</div>

<script>
let nodes=[], state={}, testingIds=new Set(), singboxEnabled=false, userTouchedIpFilter=false, loadingStartTime=null;
const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));

const trQuality = q => ({"normal":"普通", "proxy":"代理", "datacenter":"数据中心", "mobile":"移动端"}[q] || q || "-");
const trIpType = t => ({"residential":"静态住宅", "hosting":"机房 IP", "mobile":"移动网络", "proxy":"代理 IP"}[t] || t || "-");

$("admin_btn").onclick = (e) => { e.stopPropagation(); $("admin_dropdown").style.display = $("admin_dropdown").style.display==="block"?"none":"block"; };
document.onclick = () => { $("admin_dropdown").style.display = "none"; };
const openModal = id => { $(id).style.display = "flex"; };
const closeModal = id => { $(id).style.display = "none"; };

function getFilteredNodes() {
  const c = $("country_filter").value;
  const ipType = $("ip_type_filter").value;
  return nodes.filter(n => {
    if (c && n.country !== c) return false;
    if (ipType) {
      if (ipType === "residential" && !["residential", "mobile"].includes(n.ip_type)) return false;
      if (ipType === "proxy" && n.ip_type !== "proxy") return false;
      if (ipType === "hosting" && n.ip_type !== "hosting") return false;
    }
    return true;
  });
}

async function saveDomain() {
    const domain = $("bind_domain_input").value;
    const r = await fetch("./api/update_domain", {
        method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({domain})
    });
    const d = await r.json();
    if (d.ok) {
        closeModal('domain_modal');
        $("restart_modal").style.display = "flex";
        let count = 10;
        const numEl = $("countdown_num");
        const timer = setInterval(() => {
            count--;
            numEl.innerText = count;
            if (count <= 0) {
                clearInterval(timer);
                const port = location.port || "18658";
                if (domain) {
                    window.location.href = `https://${domain}:${port}${window.location.pathname}`;
                } else {
                    window.location.href = `http://${window.location.hostname}:${port}${window.location.pathname}`;
                }
            }
        }, 1000);
    } else {
        alert(d.message || "操作失败");
    }
}

async function closeWarningModal() {
    if ($("chk_ignore_warning").checked) {
        await fetch("./api/ignore_domain_warning", {method:"POST"});
    }
    closeModal('domain_warning_modal');
}

function formatUptime(seconds) {
    if (!seconds || seconds < 0) return "00:00:00";
    const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
    const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    const s = Math.floor(seconds % 60).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
}

function stableSortNodes() {
  const activeId = state.active_openvpn_node_id;
  nodes.sort((a, b) => {
    if (a.id === activeId && b.id !== activeId) return -1;
    if (b.id === activeId && a.id !== activeId) return 1;
    const latA = a.latency_ms > 0 ? a.latency_ms : 999999;
    const latB = b.latency_ms > 0 ? b.latency_ms : 999999;
    if (latA !== latB) return latA - latB;
    return (b.score || 0) - (a.score || 0);
  });
}

function render(){
  const activeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n.id === activeId);
  
  let backupHtml = "";
  let uptimeHtml = "";
  
  if (state.connected_at) {
      const upSecs = Math.floor((Date.now() - state.connected_at * 1000) / 1000);
      uptimeHtml = `<div style="margin-top:6px; font-size:13px; color:var(--text-secondary); font-family:'JetBrains Mono', monospace;">⏱️ 已连接: <span id="uptime_counter" style="color:#34d399; font-weight:bold;">${formatUptime(upSecs)}</span></div>`;
  }
  
  if (activeNode) {
    const backups = nodes.filter(n => n.probe_status === 'available' && !n.active && n.country === activeNode.country).sort((a,b) => (a.latency_ms||999) - (b.latency_ms||999)).slice(0, 3);
    if (backups.length > 0) {
      backupHtml = `<div style="margin-top: 12px; padding-top: 12px; border-top: 1px dashed rgba(255,255,255,0.1); font-size: 13px; color: var(--text-secondary);">
        <span style="margin-right: 8px;">🛡️ 同地区备选池:</span>
        ${backups.map(n => `<span class="badge" style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); margin-right: 6px;">${esc(n.ip)} (${n.latency_ms}ms)</span>`).join('')}
      </div>`;
    } else {
      backupHtml = `<div style="margin-top: 12px; padding-top: 12px; border-top: 1px dashed rgba(255,255,255,0.1); font-size: 13px; color: var(--warning);">
        ⚠️ 警告: 当前地区无可用备选节点，请在下方批量测试补充或开启自动获取
      </div>`;
    }
  }
  
  const hasAvailableNodes = nodes.some(n => n.probe_status === 'available');

  if(activeNode) {
    $("active_node_card").innerHTML = `
      <div class="active-card">
        <div style="flex: 1;">
          <span class="badge available">已连接</span> <strong style="font-size:18px;margin-left:10px;">${esc(activeNode.country)}</strong>
          <div class="mono" style="margin-top:10px; color:#a5b4fc;">${esc(activeNode.ip||activeNode.remote_host)}:${activeNode.remote_port}</div>
          ${uptimeHtml}
          ${backupHtml}
        </div>
        <button id="btn_disconnect" style="background:var(--danger);color:white;border:none; height: 38px; padding: 0 16px; border-radius: 8px; font-weight: bold; cursor: pointer;" onclick="disconnectNode()">断开连接</button>
      </div>`;
  } else if (state.is_connecting || !hasAvailableNodes) {
    if (!loadingStartTime) loadingStartTime = Date.now();
    $("active_node_card").innerHTML = `
      <div class="active-card" style="display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 35px 20px; border: 2px dashed rgba(99, 102, 241, 0.4); background: rgba(99, 102, 241, 0.05);">
        <div style="font-size: 22px; font-weight: 700; color: #a5b4fc; margin-bottom: 12px; display: flex; align-items: center; gap: 10px;">
          <svg style="animation: spin 2s linear infinite; width: 26px; height: 26px; color: #a5b4fc;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" style="opacity: 0.25;"></circle><path fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" style="opacity: 0.75;"></path></svg>
          正在批量处理节点信息
        </div>
        <div style="color: var(--text-secondary); font-size: 15px; text-align: center;">
          后台正在为您测速并筛选优质节点，约 1-5 分钟，请耐心等待！<br>
          <div style="margin-top: 12px; display: inline-block; padding: 4px 16px; background: rgba(0,0,0,0.2); border-radius: 20px; font-family: 'JetBrains Mono', monospace; font-size: 13px;">
            ⏱️ 已经耗时: <span id="loading_timer" style="color: #f59e0b; font-weight: bold; font-size: 14px;">00:00:00</span>
          </div>
        </div>
      </div>
      <style>@keyframes spin { 100% { transform: rotate(360deg); } }</style>
    `;
  } else {
    loadingStartTime = null; 
    $("active_node_card").innerHTML = `
      <div class="active-card" style="display: flex; justify-content: center; align-items: center; padding: 30px; opacity: 0.8;">
        <span style="font-size: 16px; color: var(--text-secondary);">未连接，请在下方列表选择可用节点切换。</span>
      </div>`;
  }

  const shown = getFilteredNodes();
  $("rows").innerHTML = shown.map(n => {
    const isActive = n.id === activeId;
    const rowClass = isActive ? 'class="active-row"' : '';
    const stClass = isActive ? 'available' : (n.probe_status||'not_checked');
    const stText = isActive ? '已连接' : (n.probe_status==='available'?'可用':(n.probe_status==='unavailable'?'不可用':'待测'));
    
    const isTesting = testingIds.has(n.id);
    const testBtnText = isTesting ? '测试中...' : '延迟测试';
    
    return `<tr ${rowClass}>
      <td><span class="badge ${stClass}">${stText}</span></td>
      <td style="color:${n.latency_ms>0&&n.latency_ms<150?'#34d399':'#fbbf24'};font-weight:600;">${n.latency_ms?n.latency_ms+' ms':'-'}</td>
      <td class="mono">${esc(n.ip||n.remote_host)}:${n.remote_port}</td>
      <td>${esc(n.country)}</td>
      <td><span style="font-size:12px;color:var(--text-secondary);">${trQuality(n.quality)}</span> <br> ${esc(n.owner||n.as_name||"-")}</td>
      <td><span style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;font-size:12px;">${trIpType(n.ip_type)}</span></td>
      <td>
        <button style="border-color:#34d399;color:#34d399;" ${isTesting?'disabled':''} onclick="testNode('${esc(n.id)}', event)">${testBtnText}</button>
        ${!isActive ? `<button style="background:#6366f1;color:white;border:none;" onclick="connectNode(event, '${esc(n.id)}')">切换</button>` : ''}
      </td>
    </tr>`;
  }).join("");
}

setInterval(() => {
    if (state.connected_at && $("uptime_counter")) {
        const upSecs = Math.floor((Date.now() - state.connected_at * 1000) / 1000);
        $("uptime_counter").innerText = formatUptime(upSecs);
    }
    if (loadingStartTime && $("loading_timer")) {
        const loadSecs = Math.floor((Date.now() - loadingStartTime) / 1000);
        $("loading_timer").innerText = formatUptime(loadSecs);
    }
}, 1000);

let warningShown = false; 

async function load(){
  try{
    const r=await fetch("./api/nodes"); const d=await r.json();
    nodes=d.nodes||[]; state=d.state||{};

    $("bind_domain_input").value = state.bound_domain || "";
    if (!state.bound_domain && !state.ignore_domain_warning && !warningShown) {
        openModal('domain_warning_modal');
        warningShown = true;
    }

    singboxEnabled = !!state.singbox_enabled;
    const sbBtn = $("singbox_btn");
    if(singboxEnabled){
        sbBtn.style.background="linear-gradient(135deg, #34d399, #059669)";
        sbBtn.style.color="white";
        sbBtn.innerText="恢复 Sing-box";
    } else {
        sbBtn.style.background="rgba(245, 158, 11, 0.15)";
        sbBtn.style.color="#f59e0b";
        sbBtn.innerText="接管 Sing-box";
    }
    
    const curOpts = Array.from($("country_filter").options).map(o=>o.value).filter(Boolean);
    const newOpts = Array.from(new Set(nodes.map(n=>n.country).filter(Boolean))).sort();
    if(JSON.stringify(curOpts)!==JSON.stringify(newOpts)){
      const selVal = $("country_filter").value;
      $("country_filter").innerHTML='<option value="">所有国家</option>'+newOpts.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join("");
      if(newOpts.includes(selVal)) $("country_filter").value = selVal;
    }
    
    $("net_port").value=state.port; $("net_suffix").value=state.secret_path; $("net_proxy").value=state.proxy_port; $("net_routing_mode").value=state.routing_mode;
    
    // [智能过滤逻辑] 如果用户没有手动切换过下拉框，则由系统智能控制
    if (!userTouchedIpFilter && nodes.length > 0) {
      const hasResidential = nodes.some(n => ["residential", "mobile"].includes(n.ip_type));
      if (hasResidential) {
        $("ip_type_filter").value = "residential"; 
      } else {
        $("ip_type_filter").value = ""; 
      }
    }

    stableSortNodes(); render();
  }catch(e){}
}

async function connectNode(e, id){
  const btn = e.target; btn.innerText = "连接中..."; btn.disabled = true;
  await fetch("./api/connect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
  setTimeout(load, 500);
}

async function disconnectNode(){
  if(!confirm("确定断开连接?")) return;
  const btn = $("btn_disconnect"); if(btn){ btn.innerText="断开中..."; btn.disabled=true; }
  await fetch("./api/disconnect",{method:"POST"});
  setTimeout(load, 200);
}

async function testNode(id, event){
  if(event) event.stopPropagation();
  testingIds.add(id); 
  render();
  try {
    await fetch("./api/test_node",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
  } catch(e) {}
  finally {
    testingIds.delete(id); 
    load();
  }
}

async function batchTestNodes() {
  const shown = getFilteredNodes();
  if (shown.length === 0) return alert("当前没有可测的节点");
  
  const btn = $("btn_batch_test");
  btn.disabled = true;
  btn.innerText = "测试中...";
  
  const idsToTest = shown.map(n => n.id);
  idsToTest.forEach(id => testingIds.add(id));
  render();
  
  try {
      await fetch("./api/test_nodes", {
          method: "POST", 
          headers: { "Content-Type": "application/json" }, 
          body: JSON.stringify({ ids: idsToTest })
      });
  } catch(e) {}
  finally {
      idsToTest.forEach(id => testingIds.delete(id));
      btn.disabled = false;
      btn.innerText = "批量测试本页延迟";
      load();
  }
}

async function refreshNodes(){
  $("refresh").innerText="更新中...";
  userTouchedIpFilter = false; 
  await fetch("./api/refresh_nodes",{method:"POST"});
  setTimeout(()=>{ $("refresh").innerText="更新节点"; load(); }, 2000);
}

async function toggleSingbox(){
  const btn = $("singbox_btn"); 
  const targetState = !singboxEnabled; 
  btn.disabled = true;
  btn.innerText = "处理中...";
  try{
    const r = await fetch("./api/toggle_singbox",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enable:targetState})});
    const d = await r.json();
    if(d.ok) {
      singboxEnabled = targetState;
      if(singboxEnabled){
        btn.style.background="linear-gradient(135deg, #34d399, #059669)"; btn.style.color="white"; btn.innerText="恢复 Sing-box";
      }else{
        btn.style.background="rgba(245, 158, 11, 0.15)"; btn.style.color="#f59e0b"; btn.innerText="接管 Sing-box";
      }
      alert(d.message);
    }else{
      alert(d.error);
      if(singboxEnabled){ btn.innerText="恢复 Sing-box"; } else { btn.innerText="接管 Sing-box"; }
    }
  }catch(e){ alert("请求异常"); }
  btn.disabled = false;
}

async function saveCreds(){
  const u=$("cred_u").value, p=$("cred_p").value; if(!u||!p) return alert("不能为空");
  const r = await fetch("./api/update_credentials",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u, password:p})});
  if(r.ok) { alert("保存成功"); closeModal('credentials_modal'); }
}

async function saveNetwork(){
  const payload = { port:$("net_port").value, secret_path:$("net_suffix").value, proxy_port:$("net_proxy").value, routing_mode:$("net_routing_mode").value };
  const r = await fetch("./api/update_settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const d = await r.json(); if(d.ok) { alert(d.message); if(d.restart_needed) setTimeout(()=>window.location.reload(), 3000); closeModal('network_modal'); }
}

async function logoutAdmin(){ await fetch("./api/logout",{method:"POST"}); window.location.reload(); }

$("country_filter").onchange = render;
$("ip_type_filter").onchange = () => { userTouchedIpFilter = true; render(); };
setInterval(load, 10000); load();
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = "::1" if is_ipv6 and LOCAL_PROXY_HOST in ("::", "") else ("127.0.0.1" if LOCAL_PROXY_HOST=="0.0.0.0" else LOCAL_PROXY_HOST)
        try: s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception:
            if connect_host == "::1":
                s.close(); s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5); s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
    except Exception as e: return {"ok": False, "error": f"端口不通: {e}"}
    finally:
        if s: s.close()

    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists(): return {"ok": False, "error": "虚拟网卡 tun0 未启用"}

    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        p_host = "127.0.0.1" if LOCAL_PROXY_HOST in ("::", "0.0.0.0") else LOCAL_PROXY_HOST
        cmd = ["curl", "-s", "-w", "\n%{time_total} %{http_code}", "-x", f"socks5h://{p_host}:{LOCAL_PROXY_PORT}", url, "--max-time", "5"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            if res.returncode == 0:
                lines = res.stdout.strip().splitlines()
                if len(lines) >= 2 and lines[1].endswith("200") and lines[0].strip():
                    return {"ok": True, "ip": lines[0].strip(), "latency_ms": int(float(lines[1].split()[0]) * 1000)}
        except Exception: pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb") or _curl_check_ip("http://api.ipify.org")
        if result: return result
        return {"ok": False, "error": "代理出口连接外网测试失败"}
    except Exception as e: return {"ok": False, "error": f"测试异常: {e}"}

def background_proxy_checker() -> None:
    time.sleep(60)
    while True:
        try:
            if is_connecting: time.sleep(5); continue
            res = check_proxy_health()
            if not res["ok"] and active_openvpn_node_id:
                if load_ui_config().get("routing_mode") != "fixed_ip":
                    auto_switch_node()
            # 【安全修正】将其放入 try 块内，即使清理失败也不会导致健康检测线程崩溃        
            cleanup_memory_pools()
        except Exception: pass
        time.sleep(180)
         

def active_node_pinger() -> None:
    while True:
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                node = next((n for n in read_json(NODES_FILE, []) if n.get("id") == active_openvpn_node_id), None)
                if node and (node.get("ip") or node.get("remote_host")):
                    latency = vpn_utils.ping_latency_ms(node.get("ip") or node.get("remote_host"), parse_int(node.get("remote_port")), parse_int(node.get("ping")))
                    set_state(active_node_latency=f"{latency} ms" if latency > 0 else "检测超时")
        except Exception: pass
        time.sleep(30) 

class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str: return load_ui_config().get("secret_path", "EJsW2EepxyBo9lY")

    def check_domain_binding(self) -> bool:
        cfg = load_ui_config()
        bound_domain = cfg.get("bound_domain", "")
        if not bound_domain:
            return True
            
        # 提取 Host 请求头，剔除端口号
        host_header = self.headers.get("Host", "")
        if ":" in host_header:
            host_header = host_header.rsplit(":", 1)[0]
        host_header = host_header.strip("[]") # 清除 IPv6 的括号
        
        # 校验如果不匹配，直接返回 403 拒绝响应
        if host_header.lower() != bound_domain.lower():
            self.send_response(HTTPStatus.FORBIDDEN)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>Direct IP access is disabled for security reasons. Please access via the designated domain name.</p>")
            return False
        return True

    def is_authorized(self) -> bool:
        pwd = load_ui_config().get("password")
        if not pwd: return True
        cookies = {k.strip(): v.strip() for k, v in [i.split("=", 1) for i in self.headers.get("Cookie", "").split(";") if "=" in i]}
        token = cookies.get("session")
        if token and token in active_sessions:
            if active_sessions[token]["expires"] > time.time():
                return True
            else:
                del active_sessions[token]
        return False

    def validate_path(self) -> str:
        sec = self.get_secret_path()
        if not sec: return self.path
        if self.path == f"/{sec}": self.send_response(302); self.send_header("Location", f"/{sec}/"); self.end_headers(); return ""
        pref = f"/{sec}/"
        if self.path.startswith(pref): return "/" + self.path[len(pref):]
        self.send_response(404); self.end_headers(); return ""

    def log_message(self, format: str, *args: Any) -> None: pass

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json", status)

    def do_GET(self) -> None:
        if not self.check_domain_binding(): return # 新增拦截（检测域名和ip）
        path = self.validate_path()
        if not path: return
        if not self.is_authorized():
            if path in ("/", "/index.html"): self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html")
            else: self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
                
        if path in ("/", "/index.html"): self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html")
        elif path == "/api/nodes":
            nodes = read_json(NODES_FILE, [])
            for n in nodes: n["active"] = (n.get("id") == active_openvpn_node_id)
            self.send_json({"nodes": [{k: v for k, v in n.items() if k != "config_text"} for n in nodes], "state": get_state()})            
        else: self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
       

    def do_POST(self) -> None:
        if not self.check_domain_binding(): return # 新增拦截（检测域名和ip）
        path = self.validate_path()
        if not path: return
        try:
            length = parse_int(self.headers.get("Content-Length"))
            # --- [安全修复] 防御内存耗尽攻击 (OOM DoS) ---
            if length > 524288: # 限制最大请求体为 512KB (API交互足够用了)
                self.send_response(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                self.end_headers()
                self.wfile.write(b'{"error": "Payload Too Large"}')
                return
            # ---------------------------------------------
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            
            if path == "/api/login":
                # 获取真实的客户端 IP (防代理伪装)
                client_ip = self.client_address[0]
                username_input = payload.get("username", "")
                password_input = payload.get("password", "")
                
                # 构建锁定键值：用户名 + IP
                lock_key = f"{username_input}:{client_ip}"
                now = time.time()
                
                # 获取锁定状态，默认为 0 次失败
                lock_info = failed_logins.get(lock_key, {"count": 0, "lock_until": 0.0})
                
                # 1. 检查是否在锁定惩罚期内
                if now < lock_info["lock_until"]:
                    remain_minutes = int((lock_info["lock_until"] - now) / 60) + 1
                    self.send_json({"ok": False, "error": f"出于安全考虑，该账户在当前IP下已被锁定，请 {remain_minutes} 分钟后再试。"}, HTTPStatus.FORBIDDEN)
                    return
                elif lock_info["lock_until"] > 0 and now >= lock_info["lock_until"]:
                    # 锁定时间已过，重置状态
                    lock_info = {"count": 0, "lock_until": 0.0}

                # 2. 验证账号密码
                real_user = load_ui_config().get("username", "")
                real_pass = load_ui_config().get("password", "")
                
                if password_input == real_pass and username_input == real_user:
                    # 登录成功，释放对该 用户名+IP 的失败计数
                    if lock_key in failed_logins:
                        del failed_logins[lock_key]
                    # --- [安全修复] 登录成功时，顺手清理全域已过期的僵尸 Token，防止内存泄漏 ---
                    now_time = time.time()
                    expired_tokens = [k for k, v in active_sessions.items() if v["expires"] < now_time]
                    for k in expired_tokens:
                        del active_sessions[k]
                    # -----------------------------------------------------------------------    
                    token = uuid.uuid4().hex
                    active_sessions[token] = {"expires": time.time() + 3600}
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    # 如果绑定了域名（启用了HTTPS），则强制 Cookie 走加密传输
                    is_secure = "Secure; " if load_ui_config().get("bound_domain") else ""
                    self.send_header("Set-Cookie", f"session={token}; Path=/{self.get_secret_path()}/; HttpOnly; {is_secure}SameSite=Lax; Max-Age=3600")
                    # -----------------------------------
                    self.end_headers()
                    self.wfile.write(b'{"ok":true}')
                else:
                    # 登录失败，增加错误计数
                    lock_info["count"] += 1
                    
                    if lock_info["count"] >= 5:
                        # 达到5次，锁定15分钟 (15 * 60 = 900秒)
                        lock_info["lock_until"] = now + 900
                        failed_logins[lock_key] = lock_info
                        self.send_json({"ok": False, "error": "失败次数已达5次！出于安全防护，该用户名及当前IP已被锁定15分钟。"}, HTTPStatus.FORBIDDEN)
                    else:
                        # 未达到上限，更新记录并提醒
                        failed_logins[lock_key] = lock_info
                        remain_times = 5 - lock_info["count"]
                        self.send_json({"ok": False, "error": f"凭证错误。您还有 {remain_times} 次尝试机会。"}, HTTPStatus.FORBIDDEN)
                return

            if not self.is_authorized(): self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED); return
            # ---------- 新增的域名判定和自动绑定域名证书 ----------
            if path == "/api/update_domain":
                cfg = load_ui_config()
                raw_domain = payload.get("domain", "").strip()
                clean_domain = raw_domain.replace("https://", "").replace("http://", "")
                clean_domain = clean_domain.split("/")[0].split(":")[0]
                
                old_domain = cfg.get("bound_domain", "")
                cfg["bound_domain"] = clean_domain
                (DATA_DIR / "ui_auth.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                # 如果域名发生改变，触发系统重启以便重新加载对应域名的证书
                if old_domain != clean_domain:
                    threading.Thread(target=lambda: (time.sleep(1), os._exit(0)), daemon=True).start()
                    self.send_json({"ok": True, "message": f"域名 [{clean_domain}] 绑定成功！系统正在重启以挂载 HTTPS 证书，请3秒后刷新页面。"})
                else:
                    self.send_json({"ok": True, "message": f"域名 [{clean_domain}] 已保存！"})
            # ----------------------------------------------    
            elif path == "/api/ignore_domain_warning":
                cfg = load_ui_config()
                cfg["ignore_domain_warning"] = True
                (DATA_DIR / "ui_auth.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                self.send_json({"ok": True})
            elif path == "/api/toggle_singbox":
                ok, msg = toggle_singbox(payload.get("enable", False), LOCAL_PROXY_PORT)
                self.send_json({"ok": ok, "message": msg})
            elif path == "/api/update_credentials":
                cfg = load_ui_config(); cfg["username"] = payload["username"]; cfg["password"] = payload["password"]
                (DATA_DIR / "ui_auth.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                self.send_json({"ok": True})
            elif path == "/api/update_settings":
                cfg = load_ui_config()
                r_need = (cfg.get("port") != parse_int(payload["port"]) or 
                          cfg.get("secret_path") != payload["secret_path"] or 
                          cfg.get("proxy_port") != parse_int(payload["proxy_port"]) or
                          cfg.get("ssl_cert", "") != payload.get("ssl_cert", "") or
                          cfg.get("ssl_key", "") != payload.get("ssl_key", ""))
                
                cfg.update({
                    "port": parse_int(payload["port"]), 
                    "secret_path": payload["secret_path"], 
                    "proxy_port": parse_int(payload["proxy_port"]), 
                    "routing_mode": payload.get("routing_mode", "auto"),
                    "ssl_cert": payload.get("ssl_cert", "").strip(),
                    "ssl_key": payload.get("ssl_key", "").strip()
                })
                (DATA_DIR / "ui_auth.json").write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                if r_need: threading.Thread(target=lambda: (time.sleep(1), os._exit(0)), daemon=True).start()
                self.send_json({"ok": True, "restart_needed": r_need, "message": "保存成功"})
            elif path == "/api/logout":
                cookies = {k.strip(): v.strip() for k, v in [i.split("=", 1) for i in self.headers.get("Cookie", "").split(";") if "=" in i]}
                token = cookies.get("session")
                if token and token in active_sessions:
                    del active_sessions[token]
                self.send_response(200)
                self.send_header("Set-Cookie", f"session=; Path=/{self.get_secret_path()}/; Max-Age=0")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            elif path == "/api/refresh_nodes":
                threading.Thread(target=maintain_valid_nodes, args=(True,), daemon=True).start()
                self.send_json({"ok": True})
            elif path == "/api/disconnect":
                def do_disconnect():
                    stop_active_openvpn()
                    with lock:
                        nodes = read_json(NODES_FILE, [])
                        for item in nodes: item["active"] = False
                        write_json(NODES_FILE, nodes)
                    set_state(active_openvpn_node_id="", last_check_message="手动断开", connected_at=0)
                threading.Thread(target=do_disconnect, daemon=True).start()
                self.send_json({"ok": True})
            elif path == "/api/connect":
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id", "")))})
            elif path == "/api/test_node":
                self.send_json({"ok": True, "node": test_node_by_id(str(payload.get("id") or ""))})
            elif path == "/api/test_nodes":
                test_multiple_nodes(payload.get("ids", []))
                self.send_json({"ok": True})
            else: self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc: self.send_json({"ok": False, "error": "Internal Server Error"}, HTTPStatus.INTERNAL_SERVER_ERROR)

class Tee:
    def __init__(self, file_path: str):
        self.file_path = file_path
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        # 使用 'w' 模式，每次启动程序时都会清空原有日志，重新开始记录
        self.file = open(file_path, "w", encoding="utf-8")
        self.stdout = sys.stdout
        
    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        # 仅在遇到换行时刷新磁盘，极大减少 I/O 操作
        if '\n' in data:
            self.file.flush()
            self.stdout.flush()
            
    def flush(self) -> None: 
        self.stdout.flush()
        self.file.flush()

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    tee = Tee(str(DATA_DIR / "vpngate.log")); sys.stdout = tee; sys.stderr = tee

    write_json(STATE_FILE, {"active_openvpn_node_id": "", "is_connecting": True, "connected_at": 0})
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    threading.Thread(target=daily_scheduler_loop, daemon=True).start()
    
    import ssl
    import glob
    
    cfg = load_ui_config()
    server = DualStackHTTPServer((cfg.get("host", UI_HOST), int(cfg.get("port", UI_PORT))), Handler)
    
    # === 万能智能证书嗅探逻辑 ===
    domain = cfg.get("bound_domain", "")
    if domain:
        cert_dir = f"/root/cert/{domain}"
        if os.path.exists(cert_dir):
            all_files = os.listdir(cert_dir)
            cert_file = None
            key_file = None
            
            # 1. 精准锁定私钥 (后缀为 .key，或名字包含 priv/private/key 的文件)
            for f in all_files:
                f_lower = f.lower()
                if f_lower.endswith(".key") or "priv" in f_lower or "key" in f_lower:
                    key_file = os.path.join(cert_dir, f)
                    break
                    
            # 2. 锁定公钥证书 (严格排除私钥文件，寻找 .cer, .crt, .pem 或包含 cert/fullchain 的文件)
            for f in all_files:
                full_path = os.path.join(cert_dir, f)
                if full_path == key_file:
                    continue  # 排除刚才找到的私钥，防止互相串台
                f_lower = f.lower()
                if f_lower.endswith((".cer", ".crt", ".pem")) or "cert" in f_lower or "fullchain" in f_lower:
                    cert_file = full_path
                    if "fullchain" in f_lower:  # fullchain 优先级最高，找到直接锁定
                        break
                        
            if cert_file and key_file:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                    print(f"[HTTPS 万能匹配] 成功挂载! 公钥: {os.path.basename(cert_file)} | 私钥: {os.path.basename(key_file)}", flush=True)
                except Exception as e:
                    print(f"[HTTPS 挂载失败] 证书文件格式不兼容或损坏: {e}", flush=True)
            else:
                print(f"[HTTPS 警告] 目录 {cert_dir} 存在，但未找齐完整的公钥和私钥", flush=True)
                
    server.serve_forever()

if __name__ == "__main__":
    main()