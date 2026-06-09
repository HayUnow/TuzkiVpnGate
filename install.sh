#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

# 1. Check root permissions
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 必须以 root 权限运行此脚本。请使用: sudo bash $0${PLAIN}"
    exit 1
fi

# 2. Check OS distribution and set package manager
OS_TYPE=""
PKG_MGR=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE=$ID
fi

case "$OS_TYPE" in
    ubuntu|debian)
        PKG_MGR="apt-get"
        export DEBIAN_FRONTEND=noninteractive
        ;;
    alpine)
        PKG_MGR="apk"
        ;;
    centos|rhel|rocky|almalinux|fedora|ol|amzn)
        if command -v dnf >/dev/null 2>&1; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
        fi
        ;;
    *)
        echo -e "${RED}错误: 不支持的操作系统 ($OS_TYPE)！${PLAIN}"
        exit 1
        ;;
esac

echo -e "${BLUE}==========================================================${PLAIN}"
echo -e "${BLUE}        欢迎使用 TuzkiVpnGate 本地私有化部署脚本${PLAIN}"
echo -e "${BLUE}==========================================================${PLAIN}"

echo -e "\n${YELLOW}[1/4] 正在安装系统基础依赖...${PLAIN}"
if [ "$PKG_MGR" = "apt-get" ]; then
    apt-get update -q || true
    apt-get install -y openvpn curl git ca-certificates iptables iproute2 psmisc python3
elif [ "$PKG_MGR" = "apk" ]; then
    apk update || true
    apk add openvpn curl git ca-certificates iptables iproute2 psmisc python3 bash
elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
    if [ "$OS_TYPE" != "fedora" ] && [ "$OS_TYPE" != "amzn" ]; then
        $PKG_MGR install -y epel-release || true
    fi
    $PKG_MGR install -y openvpn curl git ca-certificates iptables iproute psmisc python3 || \
    $PKG_MGR install -y openvpn curl git ca-certificates iptables iproute2 psmisc python3
fi

# 4. Set Local Installation Directory (修改为本地运行模式)
INSTALL_DIR="$(pwd)"
echo -e "\n${YELLOW}[2/4] 采用本地模式部署，当前目录: ${INSTALL_DIR}...${PLAIN}"

if [ ! -f "${INSTALL_DIR}/vpngate_manager.py" ]; then
    echo -e "${RED}错误: 未在当前目录找到 vpngate_manager.py。请确保脚本与 Python 源码在同一目录下运行！${PLAIN}"
    exit 1
fi

# 5. Configure Service
echo -e "\n${YELLOW}[3/4] 正在配置系统服务...${PLAIN}"
if command -v systemctl >/dev/null 2>&1; then
    cat > /lib/systemd/system/tuzkivpngate.service <<EOF
[Unit]
Description=TuzkiVpnGate OpenVPN Manager with HTTP/SOCKS5 Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 vpngate_manager.py
Restart=always
RestartSec=5
EnvironmentFile=-/etc/default/tuzkivpngate

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable tuzkivpngate.service
elif command -v rc-service >/dev/null 2>&1; then
    cat > /etc/init.d/tuzkivpngate <<EOF
#!/sbin/openrc-run

description="TuzkiVpnGate OpenVPN Manager with HTTP/SOCKS5 Proxy"
command="/usr/bin/python3"
command_args="${INSTALL_DIR}/vpngate_manager.py"
command_background="yes"
directory="${INSTALL_DIR}"
pidfile="/run/tuzkivpngate.pid"

depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/tuzkivpngate
    rc-update add tuzkivpngate default
fi

# 6. Configure global command shortcut "tz"
echo -e "\n${YELLOW}[4/4] 正在创建全局命令快捷接口 'tz'...${PLAIN}"
cat > /usr/bin/tz <<'EOF'
#!/usr/bin/env python3
import sys
import os
import socket
import subprocess
import time
import tty
import termios
import shutil

INSTALL_DIR = "MY_INSTALL_DIR_PLACEHOLDER"
LOG_FILE = "MY_INSTALL_DIR_PLACEHOLDER/vpngate_data/vpngate.log"

def generate_random_password() -> str:
    import string
    import random
    
    # 明确定义四种字符集
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&+-/*" # 这里明确列出你想要的特殊字符
    
    # 强制每种类型至少选一个，保证绝对安全
    pwd = [
        random.choice(lower),
        random.choice(upper),
        random.choice(digits),
        random.choice(special)
    ]
    
    # 补齐剩下的 8 位 (总共 12 位)
    all_chars = lower + upper + digits + special
    pwd += random.choices(all_chars, k=16)
    
    # 打乱顺序，防止密码前四位规律性太强
    random.shuffle(pwd)
    
    return "".join(pwd)

def generate_random_suffix():
    import random
    import string
    return "".join(random.choices(string.ascii_letters + string.digits, k=12))

def load_ui_cfg():
    import json
    path = f"{INSTALL_DIR}/vpngate_data/ui_auth.json"
    cfg = {"host": "::", "port": 18658, "secret_path": "EJsW2EepxyBo9lY", "password": ""}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    cfg[k] = v
        except Exception:
            pass
    return cfg

def save_ui_cfg(cfg):
    import json
    path = f"{INSTALL_DIR}/vpngate_data/ui_auth.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def load_state():
    import json
    path = f"{INSTALL_DIR}/vpngate_data/state.json"
    state = {"active_openvpn_node_id": "", "last_check_message": "", "is_connecting": False}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    state[k] = v
        except Exception:
            pass
    return state

def get_active_node_info():
    import json
    path = f"{INSTALL_DIR}/vpngate_data/nodes.json"
    state = load_state()
    active_id = state.get("active_openvpn_node_id")
    if not active_id:
        return None, None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                nodes = json.load(f)
                for n in nodes:
                    if n.get("id") == active_id:
                        ip = n.get("ip") or n.get("remote_host")
                        loc = n.get("location") or n.get("country") or "未知"
                        return ip, loc
        except Exception:
            pass
    return None, None

def get_public_ip():
    path = f"{INSTALL_DIR}/vpngate_data/public_ip.txt"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                ip = f.read().strip()
                if ip:
                    return ip
        except Exception:
            pass
    return "您的服务器公网IP"

def check_port_listening(port):
    for host, family in [("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)]:
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            pass
    return False

def get_service_pid(service_name="tuzkivpngate.service"):
    try:
        for pid_dir in os.listdir('/proc'):
            if pid_dir.isdigit():
                try:
                    with open(os.path.join('/proc', pid_dir, 'cmdline'), 'r') as f:
                        cmd = f.read()
                        if 'vpngate_manager.py' in cmd:
                            return pid_dir
                except Exception:
                    continue
    except Exception:
        pass
    return None

def check_service_active(service_name="tuzkivpngate.service"):
    return get_service_pid(service_name) is not None

def check_openvpn_process():
    try:
        for pid_dir in os.listdir('/proc'):
            if pid_dir.isdigit():
                try:
                    with open(os.path.join('/proc', pid_dir, 'cmdline'), 'r') as f:
                        cmd = f.read().split('\x00')[0]
                        if 'openvpn' in cmd:
                            return True
                except Exception:
                    continue
    except Exception:
        pass
    return False

def get_display_width(s):
    import re
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKH]')
    s_clean = ansi_escape.sub('', s)
    width = 0
    for char in s_clean:
        if ord(char) > 127:
            width += 2
        else:
            width += 1
    return width

def format_line(label, value, target_width=26):
    prefix = "  ● "
    w = get_display_width(label)
    padding = " " * max(0, target_width - w)
    return f"{prefix}{label}{padding}:  {value}"

def print_line(text=""):
    print(f"{text}\033[K")

def print_status():
    cfg = load_ui_cfg()
    ui_port = cfg.get("port", 18658)
    secret_path = cfg.get("secret_path", "EJsW2EepxyBo9lY")
    proxy_port = cfg.get("proxy_port", 52928)
    state = load_state()
    is_connecting = state.get("is_connecting", False)
    
    gateway_ok = check_port_listening(proxy_port)
    service_ok = check_service_active("tuzkivpngate.service")
    openvpn_ok = check_openvpn_process()
    pid = get_service_pid("tuzkivpngate.service")
    
    active_ip, active_loc = get_active_node_info()
    latency = state.get("active_node_latency", "测试中...") if active_ip else "无活动连接"
    
    green = "\033[1;32m"
    red = "\033[1;31m"
    reset = "\033[0m"
    bold = "\033[1m"
    yellow = "\033[1;33m"
    
    backend_status = f"{green}[已激活] (PID: {pid}){reset}" if (service_ok and pid) else f"{red}[未启动]{reset}"
    
    if is_connecting:
        gateway_status = f"{yellow}[切换中...]{reset}"
        openvpn_status = f"{yellow}[{state.get('active_node_latency') or '连接中'}...]{reset}"
    else:
        gateway_status = f"{green}[已激活]{reset}" if gateway_ok else f"{red}[未启动]{reset}"
        openvpn_status = f"{green}[已连接]{reset}" if openvpn_ok else f"{red}[未连接]{reset}"
    
    print_line("=======================================================")
    print_line(f"               {bold}TuzkiVpnGate 管理终端 v2.0{reset}                  ")
    print_line("=======================================================")
    print_line("【核心服务状态】")
    print_line(format_line(f"代理网关 (Port {proxy_port})", gateway_status))
    print_line(format_line(f"管理后台 (Port {ui_port})", backend_status))
    print_line(format_line("连接核心 (OpenVPN)", openvpn_status))
    # 在这个位置插入域名绑定状态提示：
    bound = cfg.get("bound_domain", "")
    if bound:
        # 如果绑定了域名，只显示 HTTPS 安全访问地址
        print_line(format_line("面板域名 (防IP扫描)", f"{green}{bound}{reset}"))
        print_line(format_line("安全访问地址", f"{yellow}https://{bound}:{ui_port}/{secret_path}/{reset}"))
    else:
        # 否则（未绑定域名），才去计算并显示 HTTP 的 IP 访问地址
        host_cfg = cfg.get("host", "::")
        if host_cfg in ("127.0.0.1", "localhost"):
            login_ip = "127.0.0.1"
        elif host_cfg == "::1":
            login_ip = "[::1]"
        elif host_cfg == "::":
            login_ip = get_public_ip()
        else:
            login_ip = f"[{host_cfg}]" if ":" in host_cfg else host_cfg
            
        print_line(format_line("网页登录地址", f"{yellow}http://{login_ip}:{ui_port}/{secret_path}/{reset}"))

    print_line(format_line("网页管理账号", cfg.get("username", "未配置")))
    curr_pwd = cfg.get("password", "")
    masked_pwd = curr_pwd if len(curr_pwd) <= 4 else curr_pwd[:3] + "********" + curr_pwd[-2:]
    print_line(format_line("网页管理密码", masked_pwd))
    print_line()
    print_line("【活动节点状态】")
    if is_connecting:
        connecting_msg = state.get('last_check_message') or '正在建立加密隧道并验证路由规则...'
        print_line(format_line("节点状态", f"{yellow}{connecting_msg}{reset}"))
    elif active_ip:
        proxy_ip = state.get("proxy_ip", "-")
        proxy_latency = state.get("proxy_latency_ms", 0)
        proxy_ok = state.get("proxy_ok", False)
        
        print_line(format_line("节点 IP (入口)", active_ip))
        print_line(format_line("节点地区", active_loc))
        print_line(format_line("节点延迟 (直连测试)", latency))
    else:
        print_line(format_line("节点状态", "无活动连接"))
    print_line()
    local_proxy = state.get("local_proxy", f"http://127.0.0.1:{proxy_port}")
    import urllib.parse
    try:
        parsed = urllib.parse.urlsplit(local_proxy)
        proxy_host = parsed.hostname or "127.0.0.1"
        proxy_port = parsed.port or proxy_port
    except Exception:
        proxy_host = "127.0.0.1"
        proxy_port = proxy_port
    
    if proxy_host == "::":
        socks_addr = "127.0.0.1"
    elif ":" in proxy_host:
        socks_addr = f"[{proxy_host}]"
    else:
        socks_addr = proxy_host

    print_line("【使用方法】")
    print_line(f"  export http_proxy=socks5://{socks_addr}:{proxy_port}")
    print_line(f"  export https_proxy=socks5://{socks_addr}:{proxy_port}")
    print_line("=======================================================")

def run_service_cmd(cmd):
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", cmd, "tuzkivpngate.service"])
    elif shutil.which("rc-service"):
        subprocess.run(["rc-service", "tuzkivpngate", cmd])
    else:
        print("未检测到支持的服务管理器 (systemd/OpenRC)")

def start_service():
    print("正在启动 TuzkiVpnGate 服务...", flush=True)
    run_service_cmd("start")
    print("已发送启动指令。")
    time.sleep(1)

def stop_service():
    print("正在停止 TuzkiVpnGate 服务...", flush=True)
    run_service_cmd("stop")
    print("已发送停止指令。")
    time.sleep(1)

def restart_service():
    print("正在重启 TuzkiVpnGate 服务...", flush=True)
    run_service_cmd("restart")
    print("已发送重启指令。")
    time.sleep(1)

def show_logs():
    print("正在查看 TuzkiVpnGate 日志 (按 Ctrl+C 退出)...", flush=True)
    if os.path.exists(LOG_FILE):
        try:
            subprocess.run(["tail", "-f", "-n", "50", LOG_FILE])
        except KeyboardInterrupt:
            pass
    else:
        print(f"日志文件不存在: {LOG_FILE}")
        time.sleep(2)

def uninstall_service():
    confirm = input("确定要完全卸载 TuzkiVpnGate 吗？(y/N): ")
    if confirm.lower() == 'y':
        print("正在完全卸载 TuzkiVpnGate...", flush=True)
        stop_service()
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "disable", "tuzkivpngate.service"])
            try:
                os.unlink("/lib/systemd/system/tuzkivpngate.service")
            except Exception:
                pass
        elif shutil.which("rc-service"):
            subprocess.run(["rc-update", "del", "tuzkivpngate"])
            try:
                os.unlink("/etc/init.d/tuzkivpngate")
            except Exception:
                pass
        try:
            os.unlink("/usr/bin/tz")
        except Exception:
            pass
        subprocess.run(["rm", "-rf", INSTALL_DIR])
        print("TuzkiVpnGate 已卸载！")
        sys.exit(0)
    else:
        print("已取消卸载。")
        time.sleep(1)

def ask_restart():
    ans = input("配置已保存。是否立即重启服务生效？(Y/n): ").strip().lower()
    if ans in ('', 'y', 'yes'):
        print("正在重启 TuzkiVpnGate 服务...", flush=True)
        restart_service()
        print("服务已重启。")
        time.sleep(1.5)

def configure_web():
    cfg = load_ui_cfg()
    while True:
        print("\033[H\033[J", end="")
        print("=======================================================")
        print("               网页绑定与地址后缀配置                  ")
        print("=======================================================")
        print(f"  [1] 切换绑定地址 (当前: {cfg.get('host', '0.0.0.0')})")
        print(f"  [2] 随机重置安全后缀 (当前: {cfg.get('secret_path', '')})")
        # 修改这里：增加显示和解除域名绑定的选项
        bound_domain = cfg.get('bound_domain', '')
        print(f"  [3] 解除域名限制/防探测 (当前绑定: {bound_domain if bound_domain else '未绑定'})")
        print("  [4] 返回主菜单")
        print("=======================================================")
        print("请直接输入数字键 [1-4] 快速执行：", end="", flush=True)

        key = getch()
        if key == '1':
            print("\033[H\033[J", end="")
            print("选择网页登录绑定地址：")
            print("  1. 仅允许本地 IPv4 登录 (127.0.0.1 - 更安全)")
            print("  2. 允许 IPv4 公网登录 (0.0.0.0)")
            print("  3. 允许 IPv4 & IPv6 双栈公网登录 (:: - 推荐)")
            print("  4. 仅允许本地 IPv6 登录 (::1)")
            sel = input("请选择 (1/2/3/4, 默认3): ").strip()
            if sel == '1':
                cfg['host'] = "127.0.0.1"
            elif sel == '2':
                cfg['host'] = "0.0.0.0"
            elif sel == '4':
                cfg['host'] = "::1"
            else:
                cfg['host'] = "::"
            save_ui_cfg(cfg)
            print(f"绑定地址已更新为: {cfg['host']}")
            ask_restart()
            break
        elif key == '2':
            print("\033[H\033[J", end="")
            new_path = generate_random_suffix()
            cfg['secret_path'] = new_path
            save_ui_cfg(cfg)
            print("安全登录后缀已随机重置成功！")
            print(f"您的全新安全登录后缀为: {new_path}")
            display_host = cfg['host']
            if ":" in display_host:
                display_host = f"[{display_host}]"
            print(f"新的访问路径为: http://{display_host}:{cfg['port']}/{new_path}/")
            ask_restart()
            break
        elif key == '3':
            print("\033[H\033[J", end="")
            cfg['bound_domain'] = ""
            save_ui_cfg(cfg)
            print("域名绑定已解除！现在已恢复直接通过 IP 访问面板的功能。")
            input("\n按回车键返回...")
            # 解除限制不需要重启服务，实时生效
        
        elif key == '4' or key == 'q' or key == '\x03':
            break

def configure_port():
    cfg = load_ui_cfg()
    while True:
        print("\033[H\033[J", end="")
        print("=======================================================")
        print("                      端口配置菜单                     ")
        print("=======================================================")
        print(f"1) 网页管理端口: {cfg.get('port', 18658)}")
        print(f"2) 代理出站端口: {cfg.get('proxy_port', 52928)}")
        print("3) 返回主菜单")
        print("-------------------------------------------------------")
        key = input("请选择操作 (1-3): ").strip()
        if key == '1':
            try:
                val = input("请输入新的网页管理端口 (1-65535, 按回车取消): ").strip()
                if val:
                    port = int(val)
                    if 1 <= port <= 65535:
                        cfg['port'] = port
                        save_ui_cfg(cfg)
                        print(f"网页管理端口已更新为: {port}")
                        ask_restart()
                    else:
                        print("错误: 端口范围必须在 1 至 65535 之间。")
                        time.sleep(2)
            except ValueError:
                print("错误: 输入必须是数字。")
                time.sleep(2)
        elif key == '2':
            try:
                val = input("请输入新的代理出站端口 (1024-65535, 按回车取消): ").strip()
                if val:
                    port = int(val)
                    if 1024 <= port <= 65535:
                        cfg['proxy_port'] = port
                        save_ui_cfg(cfg)
                        print(f"代理出站端口已更新为: {port}")
                        ask_restart()
                    else:
                        print("错误: 端口范围必须在 1024 至 65535 之间。")
                        time.sleep(2)
            except ValueError:
                print("错误: 输入必须是数字。")
                time.sleep(2)
        elif key == '3' or key == 'q' or key == '\x03':
            break

def configure_credentials():
    cfg = load_ui_cfg()
    while True:
        print("\033[H\033[J", end="")
        print("=======================================================")
        print("                    管理账号密码管理                   ")
        print("=======================================================")
        curr_uname = cfg.get('username', '未配置')
        curr_pwd = cfg.get('password', '')
        masked_pwd = curr_pwd if len(curr_pwd) <= 4 else curr_pwd[:3] + "********" + curr_pwd[-2:]
        print(f"当前管理账号: {curr_uname}")
        print(f"当前管理密码: {masked_pwd}")
        print("  [1] 自定义修改账号密码")
        print("  [2] 随机重置安全密码")
        print("  [3] 返回主菜单")
        print("=======================================================")
        print("请直接输入数字键 [1-3] 快速执行：", end="", flush=True)
        
        key = getch()
        if key == '1':
            print("\033[H\033[J", end="")
            new_uname = input(f"请输入新管理账号 (回车默认 {curr_uname}): ").strip()
            if not new_uname:
                new_uname = curr_uname
            new_pwd = input("请输入新管理密码 (不能为空): ").strip()
            if not new_pwd:
                print("错误: 密码不能为空！")
                time.sleep(2)
                continue
            cfg['username'] = new_uname
            cfg['password'] = new_pwd
            save_ui_cfg(cfg)
            print("账号密码修改成功！")
            print(f"您的新管理账号: {new_uname}")
            print(f"您的新管理密码: {new_pwd}")
            input("\n按任意键返回菜单...")
        elif key == '2':
            print("\033[H\033[J", end="")
            new_pwd = generate_random_password()
            cfg['password'] = new_pwd
            save_ui_cfg(cfg)
            print("密码随机重置成功！")
            print(f"您的全新12位安全密码为: {new_pwd}")
            print("密码已保存在本地，不需要重启服务，刷新浏览器即可登录。")
            input("\n按任意键返回菜单...")
        elif key == '3' or key == 'q' or key == '\x03':
            break

def getch():
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        return sys.stdin.read(1)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def main():
    if os.geteuid() != 0:
        print("错误: 必须以 root 权限运行此命令。")
        sys.exit(1)
        
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "start":
            start_service()
        elif cmd == "stop":
            stop_service()
        elif cmd == "restart":
            restart_service()
        elif cmd == "status":
            print("\033[?1049h\033[?25l\033[H\033[J", end="", flush=True)
            try:
                while True:
                    print("\033[H", end="")
                    print_status()
                    print_line("\n\033[1;33m提示: 当前为静态页面。按 [回车键/Enter] 手动刷新状态，按 [q] 或 [Ctrl+C] 退出...\033[0m")
                    print("\033[J", end="", flush=True)
                    key = getch()
                    if key in ('q', 'Q', '\x03'):
                        break
                    if key in ('\r', '\n', '\x0a', '\x0d'):
                        continue
            except KeyboardInterrupt:
                pass
            finally:
                print("\033[?1049l\033[?25h", end="", flush=True)
        elif cmd == "logs":
            show_logs()
        elif cmd == "uninstall":
            uninstall_service()
        elif cmd == "web":
            configure_web()
        elif cmd == "port":
            configure_port()
        elif cmd == "password":
            configure_credentials()
        else:
            print("未知命令。可用命令: start, stop, restart, status, logs, uninstall, web, port, password")
        sys.exit(0)
        
    options = {
        '1': ("启动服务 (tz start)", start_service),
        '2': ("停止服务 (tz stop)", stop_service),
        '3': ("重启服务 (tz restart)", restart_service),
        '4': ("日志监控 (tz logs)", show_logs),
        '5': ("网页配置 (tz web)", configure_web),
        '6': ("端口配置 (tz port)", configure_port),
        '7': ("账号密码 (tz password)", configure_credentials),
        '8': ("完全卸载 (tz uninstall)", uninstall_service),
        '0': ("退出终端", None)
    }
    
    print("\033[?1049h\033[?25l\033[H\033[J", end="", flush=True)
    try:
        need_redraw = True
        while True:
            if need_redraw:
                print("\033[H", end="")
                print_status()
                
                bold = "\033[1m"
                reset = "\033[0m"
                green = "\033[1;32m"
                
                print_line(f"【{bold}终端指令菜单栏{reset}】")
                for key in sorted(options.keys()):
                    if key == '0':
                        continue
                    name, _ = options[key]
                    print_line(f"  {green}[{key}]{reset} {name}")
                print_line(f"  {green}[0]{reset} {options['0'][0]}")
                print_line("=======================================================")
                print_line("提示: 当前为静态页面。按 [回车键/Enter] 手动刷新状态。")
                print("请直接输入数字键 [0-8] 快速选择执行：\033[K", end="", flush=True)
                print("\033[J", end="", flush=True)
                need_redraw = False
                
            try:
                key = getch()
            except KeyboardInterrupt:
                break
                
            if key == '\x03' or key == 'q' or key == 'Q' or key == '0':
                break
                
            if key in ('\r', '\n', '\x0a', '\x0d'):
                need_redraw = True
                continue
                
            if key in options:
                name, func = options[key]
                if func is None:
                    break
                print("\033[?1049l\033[?25h", end="", flush=True)
                print(f"正在执行: {name}...\n")
                try:
                    func()
                except Exception as e:
                    print(f"执行出错: {e}")
                if func not in (start_service, stop_service, restart_service,
                                configure_web, configure_port, configure_credentials, show_logs):
                    input("\n操作已完成，按回车键返回主菜单...")
                print("\033[?1049h\033[?25l\033[H\033[J", end="", flush=True)
                need_redraw = True
    finally:
        print("\033[?1049l\033[?25h", end="", flush=True)

if __name__ == "__main__":
    main()
EOF

sed -i "s|MY_INSTALL_DIR_PLACEHOLDER|${INSTALL_DIR}|g" /usr/bin/tz
chmod +x /usr/bin/tz

# 7. Configure Custom parameters (First-time installation check)
AUTH_FILE="${INSTALL_DIR}/vpngate_data/ui_auth.json"
mkdir -p "${INSTALL_DIR}/vpngate_data"

is_custom="n"
if [ ! -f "$AUTH_FILE" ]; then
    if [ -t 0 ]; then
        echo -e "\n${YELLOW}检测到是首次安装，是否需要自定义配置网页端参数（端口/安全后缀/登录账号密码）？${PLAIN}"
        read -p "是否自定义配置？[y/N]: " is_custom
    else
        echo -e "\n${YELLOW}检测到是非交互式/无TTY环境安装，已自动跳过网页端参数自定义配置，采用默认随机参数部署。${PLAIN}"
    fi
    
    UI_PORT=18658
    SECRET_PATH=$(python3 -c "import random, string; print(''.join(random.choices(string.ascii_letters + string.digits, k=12)))")
    UI_PASSWORD=$(python3 -c "import random, string; lower = string.ascii_lowercase; upper = string.ascii_uppercase; digits = string.digits; special = '!@#$%^&+-/*'; pwd = [random.choice(lower), random.choice(upper), random.choice(digits), random.choice(special)] + random.choices(lower + upper + digits + special, k=16); random.shuffle(pwd); print(''.join(pwd))")
    UI_USERNAME=$(python3 -c "import random, string; c=string.ascii_letters+string.digits; print(next(u for _ in iter(int,1) for u in [''.join(random.choices(c, k=12))] if u[0].isalpha() and any(x.islower() for x in u) and any(x.isupper() for x in u) and any(x.isdigit() for x in u)))")

    if [[ "$is_custom" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "请输入自定义管理端口 [1-65535, 默认 18658]: " input_port
            if [ -z "$input_port" ]; then UI_PORT=18658; break; fi
            if [[ "$input_port" =~ ^[0-9]+$ ]] && [ "$input_port" -ge 1 ] && [ "$input_port" -le 65535 ]; then UI_PORT=$input_port; break; else echo -e "${RED}输入错误!${PLAIN}"; fi
        done
        while true; do
            read -p "请输入网页登录自定义安全后缀 [字母与数字组合, 默认随机]: " input_suffix
            if [ -z "$input_suffix" ]; then break; fi
            if [[ "$input_suffix" =~ ^[A-Za-z0-9]+$ ]]; then SECRET_PATH=$input_suffix; break; else echo -e "${RED}输入错误!${PLAIN}"; fi
        done
        read -p "请输入登录账号 [默认 $UI_USERNAME]: " input_user
        if [ -n "$input_user" ]; then UI_USERNAME=$input_user; fi
        while true; do
            read -p "请输入登录密码 [默认随机生成, 建议包含字母、数字与符号]: " input_pass
            if [ -z "$input_pass" ]; then break; fi
            if [ ${#input_pass} -ge 4 ]; then UI_PASSWORD=$input_pass; break; else echo -e "${RED}输入错误: 密码长度不能少于 4 位！${PLAIN}"; fi
        done
    fi

    python3 -c "
import json
cfg = {
    'host': '::',
    'port': int('$UI_PORT'),
    'secret_path': '$SECRET_PATH',
    'username': '$UI_USERNAME',
    'password': '$UI_PASSWORD'
}
with open('$AUTH_FILE', 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
"
fi

# 8. Start service & network parameters
echo -e "\n正在优化网络参数 (配置反向路径过滤 rp_filter=2 以支持策略路由)..."
if [ -d "/etc/sysctl.d" ]; then
    cat > /etc/sysctl.d/99-tuzkivpngate.conf <<EOF
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
    sysctl -p /etc/sysctl.d/99-tuzkivpngate.conf >/dev/null 2>&1 || true
else
    if ! grep -q "net.ipv4.conf.all.rp_filter" /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.rp_filter = 2" >> /etc/sysctl.conf
        echo "net.ipv4.conf.default.rp_filter = 2" >> /etc/sysctl.conf
    else
        sed -i 's/net.ipv4.conf.all.rp_filter\s*=\s*[0-9]/net.ipv4.conf.all.rp_filter = 2/g' /etc/sysctl.conf
        sed -i 's/net.ipv4.conf.default.rp_filter\s*=\s*[0-9]/net.ipv4.conf.default.rp_filter = 2/g' /etc/sysctl.conf
    fi
    sysctl -p >/dev/null 2>&1 || true
fi
echo "2" > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
echo "2" > /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null || true

echo -e "\n正在启动 TuzkiVpnGate 服务并初始化网络..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart tuzkivpngate.service || true
elif command -v rc-service >/dev/null 2>&1; then
    rc-service tuzkivpngate restart || true
fi

echo -e "\n正在等待 TuzkiVpnGate 首次获取节点并建立加密通道 (此过程可能需要 1-3 分钟，请耐心等待)..."
ACTIVE_ID=""
for i in {1..90}; do
    if [ -f "${INSTALL_DIR}/vpngate_data/state.json" ]; then
        ACTIVE_ID=$(python3 -c "import json; print(json.load(open('${INSTALL_DIR}/vpngate_data/state.json')).get('active_openvpn_node_id', ''))" 2>/dev/null || echo "")
        IS_CONN=$(python3 -c "import json; print(json.load(open('${INSTALL_DIR}/vpngate_data/state.json')).get('is_connecting', False))" 2>/dev/null || echo "False")
        if [ "$IS_CONN" = "False" ] || [ "$IS_CONN" = "false" ]; then
            if [ -n "$ACTIVE_ID" ]; then
                echo -e "  -> ${GREEN}[已就绪]${PLAIN} 首次节点连接成功，活动节点: ${GREEN}$ACTIVE_ID${PLAIN}"
                break
            fi
        fi
    fi
    sleep 1
done

SECRET_PATH="EJsW2EepxyBo9lY"
USERNAME="未配置"
PASSWORD="未配置"
UI_PORT=18658
if [ -f "$AUTH_FILE" ]; then
    SECRET_PATH=$(python3 -c "import json; print(json.load(open('$AUTH_FILE')).get('secret_path', 'EJsW2EepxyBo9lY'))" 2>/dev/null || echo "EJsW2EepxyBo9lY")
    USERNAME=$(python3 -c "import json; print(json.load(open('$AUTH_FILE')).get('username', '未配置'))" 2>/dev/null || echo "未配置")
    PASSWORD=$(python3 -c "import json; print(json.load(open('$AUTH_FILE')).get('password', '未配置'))" 2>/dev/null || echo "未配置")
    UI_PORT=$(python3 -c "import json; print(json.load(open('$AUTH_FILE')).get('port', 18658))" 2>/dev/null || echo "18658")
fi

echo -e "正在获取 VPS 公网 IP..."
PUBLIC_IP=$(curl -s --max-time 3 https://api.ipify.org || echo "您的服务器公网IP")
echo -n "$PUBLIC_IP" > "${INSTALL_DIR}/vpngate_data/public_ip.txt"

echo -e "\n${GREEN}==========================================================${PLAIN}"
echo -e "${GREEN}             TuzkiVpnGate 源码私有化部署已完成！${PLAIN}"
echo -e "${GREEN}==========================================================${PLAIN}"
echo -e "  * 网页控制面板:  ${BLUE}http://${PUBLIC_IP}:${UI_PORT}/${SECRET_PATH}/${PLAIN}"
echo -e "  * 网页管理账号:  ${YELLOW}${USERNAME}${PLAIN}"
echo -e "  * 网页管理密码:  ${YELLOW}${PASSWORD}${PLAIN}"
echo -e "  * SOCKS5 代理:   ${BLUE}http://127.0.0.1:52928/${PLAIN}"
echo -e " --------------------------------------------------------"
echo -e "  * 快速状态指令:   ${YELLOW}tz status${PLAIN}  或  ${YELLOW}tz${PLAIN}"
echo -e "=========================================================="
echo