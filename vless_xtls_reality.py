#!/usr/bin/env python3
# ============================================================
#   VLESS + XTLS-Vision + Reality 一键部署脚本
#   适用系统：Ubuntu 20.04 / 22.04 / 24.04
#   运行方式：sudo python3 setup_reality.py
# ============================================================

import subprocess
import re
import json
import random
import os
import sys
import urllib.request

# ── 颜色输出 ──────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"{GREEN}✓ {msg}{RESET}")
def info(msg): print(f"{BLUE}▶ {msg}{RESET}")
def warn(msg): print(f"{YELLOW}⚠ {msg}{RESET}")
def err(msg):  print(f"{RED}✗ {msg}{RESET}")

# ── 执行系统命令 ──────────────────────────────────────────
def run(cmd, check=False):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        err(f"命令失败: {cmd}")
        err(result.stderr)
        sys.exit(1)
    return result.stdout.strip(), result.stderr.strip()

# ── 获取本机公网 IP ───────────────────────────────────────
def get_public_ip():
    for url in ["https://api.ipify.org", "https://ifconfig.me", "https://icanhazip.com"]:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    return "YOUR_SERVER_IP"

# ══════════════════════════════════════════════════════════
def main():
    print(f"\n{BOLD}{'═'*54}")
    print("   VLESS + XTLS-Vision + Reality  一键部署")
    print(f"{'═'*54}{RESET}\n")

    # ── 检查 root 权限 ────────────────────────────────────
    if os.geteuid() != 0:
        err("请使用 root 权限运行：sudo python3 setup_reality.py")
        sys.exit(1)

    # ── Step 1: 安装 Xray ─────────────────────────────────
    info("[1/5] 安装 Xray-core ...")
    run('bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install', check=True)
    if os.path.exists("/usr/local/bin/xray"):
        ok("Xray 安装成功")
    else:
        err("Xray 安装失败，请检查网络后重试")
        sys.exit(1)

    # ── Step 2: 生成 UUID ─────────────────────────────────
    info("[2/5] 生成 UUID ...")
    uuid, _ = run("xray uuid")
    if not uuid:
        err("UUID 生成失败")
        sys.exit(1)
    ok(f"UUID: {uuid}")

    # ── Step 3: 生成 Reality 密钥对 ───────────────────────
    info("[3/5] 生成 Reality 密钥对 ...")
    key_output, _ = run("xray x25519")
    private_key = ""
    public_key  = ""
    m_priv = re.search(r'PrivateKey:\s*(\S+)', key_output)
    m_pub  = re.search(r'Password \(PublicKey\):\s*(\S+)', key_output)
    private_key = m_priv.group(1) if m_priv else ""
    public_key  = m_pub.group(1)  if m_pub  else ""

    if not private_key or not public_key:
        err("密钥生成失败")
        sys.exit(1)

    ok(f"Private Key: {private_key}")
    ok(f"Public Key:  {public_key}")

    # ── Step 4: 生成随机 ShortId ──────────────────────────
    short_id = ''.join(random.choices('0123456789abcdef', k=8))
    ok(f"Short ID:    {short_id}")

    # ── 检测端口占用 ──────────────────────────────────────
    import socket
    def port_in_use(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
                return False
            except OSError:
                return True

    listen_port = 443
    if port_in_use(443):
        warn("443 端口已被占用，自动切换到 8443")
        listen_port = 8443
    else:
        ok("443 端口可用")

    # ── Step 5: 写入 Xray 配置文件 ────────────────────────
    info("[4/5] 写入配置文件 ...")
    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "port": listen_port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": uuid,
                            "flow": "xtls-rprx-vision"
                        }
                    ],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": "www.microsoft.com:443",
                        "xver": 0,
                        "serverNames": ["www.microsoft.com"],
                        "privateKey": private_key,
                        "shortIds": [short_id]
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }

    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    with open("/usr/local/etc/xray/config.json", "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    ok("配置文件写入成功：/usr/local/etc/xray/config.json")

    # ── Step 6: 启动服务 ──────────────────────────────────
    info("[5/5] 启动 Xray 服务 ...")
    run("systemctl daemon-reload")
    run("systemctl restart xray")
    run("systemctl enable xray")

    status, _ = run("systemctl is-active xray")
    if status == "active":
        ok("Xray 服务运行正常 (active)")
    else:
        err(f"服务异常，状态：{status}")
        out, _ = run("journalctl -u xray --no-pager -n 20")
        print(out)
        sys.exit(1)

    # ── 获取公网 IP ───────────────────────────────────────
    info("获取服务器公网 IP ...")
    public_ip = get_public_ip()
    ok(f"公网 IP: {public_ip}")

    # ── 生成 VLESS 分享链接 ───────────────────────────────
    vless_link = (
        f"vless://{uuid}@{public_ip}:{listen_port}"
        f"?encryption=none"
        f"&flow=xtls-rprx-vision"
        f"&security=reality"
        f"&sni=www.microsoft.com"
        f"&fp=chrome"
        f"&pbk={public_key}"
        f"&sid={short_id}"
        f"&type=tcp"
        f"#GCP-Reality"
    )

    # ── 输出结果 ──────────────────────────────────────────
    print(f"\n{BOLD}{GREEN}{'═'*54}")
    print("  ✅  部署完成！")
    print(f"{'═'*54}{RESET}")

    print(f"""
{BOLD}── 服务器信息 ──────────────────────────────────────{RESET}
  IP 地址   : {public_ip}
  端口      : {listen_port}
  协议      : VLESS + XTLS-Vision + Reality

{BOLD}── 客户端参数 ──────────────────────────────────────{RESET}
  UUID      : {uuid}
  Public Key: {public_key}
  Short ID  : {short_id}
  SNI       : www.microsoft.com
  指纹      : chrome

{BOLD}── 分享链接（复制到客户端一键导入）────────────────{RESET}
{GREEN}{vless_link}{RESET}
""")

    # ── 保存配置到本地文件 ────────────────────────────────
    save_path = "/root/reality_config.txt"
    with open(save_path, "w") as f:
        f.write(f"服务器 IP   : {public_ip}\n")
        f.write(f"端口        : {listen_port}\n")
        f.write(f"UUID        : {uuid}\n")
        f.write(f"Public Key  : {public_key}\n")
        f.write(f"Private Key : {private_key}\n")
        f.write(f"Short ID    : {short_id}\n")
        f.write(f"\nVLESS 链接  :\n{vless_link}\n")
    ok(f"配置已保存至 {save_path}")

    print(f"""
{YELLOW}{BOLD}⚠ 还需手动完成：{RESET}
{YELLOW}  1. GCP 控制台 → VPC 网络 → 防火墙 → 添加规则
     入站 / TCP / 端口 {listen_port} / 来源 0.0.0.0/0
  2. 复制上方 vless:// 链接到客户端导入即可{RESET}
""")

if __name__ == "__main__":
    main()