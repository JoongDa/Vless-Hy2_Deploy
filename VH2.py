#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VH2.py — VLESS + Hysteria2 统一部署管理脚本
仓库: https://github.com/JoongDa/Vless-Hy2_Deploy
"""

import ipaddress
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

# ══════════════════════════════════════════
#  常量
# ══════════════════════════════════════════
# VLESS / Xray
XRAY_BIN     = Path("/usr/local/bin/xray")
XRAY_CFG     = Path("/usr/local/etc/xray/config.json")
XRAY_SVC     = "xray.service"
VLESS_LINK   = Path("/root/vless_config.txt")

# Hysteria2
HY2_BIN      = Path("/usr/local/bin/hysteria")
HY2_CFG      = Path("/etc/hysteria/config.yaml")
HY2_SVC      = "hysteria-server.service"
HY2_LINK     = Path("/etc/hysteria/hy2_link.txt")

# 证书
LE_DIR       = Path("/etc/letsencrypt/live")
SSL_DIR      = Path("/etc/ssl/private")

# ANSI 颜色
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ══════════════════════════════════════════
#  工具函数
# ══════════════════════════════════════════
def run(cmd, **kw):
    return subprocess.run(
        cmd, shell=isinstance(cmd, str),
        executable="/bin/bash" if isinstance(cmd, str) else None, **kw
    )

def ok(msg):   print(f"{GREEN}✓  {msg}{RESET}")
def err(msg):  print(f"{RED}✗  {msg}{RESET}")
def warn(msg): print(f"{YELLOW}⚠  {msg}{RESET}")
def info(msg): print(f"{CYAN}→  {msg}{RESET}")
def banner(t): print(f"\n{BOLD}{CYAN}── {t} ──{RESET}")

def require_root():
    if os.geteuid() != 0:
        err("请以 root 运行：sudo python3 VH2.py")
        sys.exit(1)

def rand_pass(n=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(n))

def validate_port(prompt, default=None):
    hint = f"（默认 {default}）" if default else ""
    while True:
        raw = input(f"{prompt}{hint}：").strip()
        if not raw and default:
            return default
        try:
            p = int(raw)
            if 1 <= p <= 65535:
                return p
            print("端口范围 1-65535")
        except ValueError:
            print("请输入数字")

def get_public_ip():
    for cmd in [
        "curl -4 -s --max-time 5 https://api.ipify.org",
        "curl -4 -s --max-time 5 ifconfig.me",
        "curl -4 -s --max-time 5 ip.sb",
    ]:
        r = run(cmd, capture_output=True, text=True)
        ip = r.stdout.strip()
        try:
            ipaddress.IPv4Address(ip)
            return ip
        except Exception:
            continue
    return input("无法自动获取 IP，请手动输入公网 IPv4：").strip()

def svc_active(name):
    return run(f"systemctl is-active {name}",
               capture_output=True).returncode == 0

def svc_status_str(name):
    active = svc_active(name)
    return f"{GREEN}运行中{RESET}" if active else f"{RED}未运行{RESET}"

def press_enter():
    input(f"\n{CYAN}按回车继续...{RESET}")

# ══════════════════════════════════════════
#  证书模块（共享）
# ══════════════════════════════════════════
def get_letsencrypt(domain: str):
    """申请 Let's Encrypt 证书，返回 (cert, key) 或 None"""
    info(f"正在为 {domain} 申请 Let's Encrypt 证书...")
    if not shutil.which("certbot"):
        info("安装 certbot...")
        run("apt-get install -y certbot", check=True)

    nginx_up = svc_active("nginx")
    if nginx_up:
        run("systemctl stop nginx")
    try:
        r = run(
            f"certbot certonly --standalone --non-interactive "
            f"--agree-tos --register-unsafely-without-email -d {domain}",
            capture_output=True, text=True
        )
        if r.returncode != 0:
            err("证书申请失败：\n" + r.stderr[-600:])
            return None
        cert = str(LE_DIR / domain / "fullchain.pem")
        key  = str(LE_DIR / domain / "privkey.pem")
        ok(f"证书申请成功")
        # 自动续期
        existing = run("crontab -l", capture_output=True, text=True).stdout
        if "certbot renew" not in existing:
            cron = "0 3 * * * certbot renew --quiet && systemctl restart xray hysteria-server"
            run(f'(crontab -l 2>/dev/null; echo "{cron}") | crontab -')
            ok("已设置证书自动续期（每天凌晨 3 点）")
        return cert, key
    finally:
        if nginx_up:
            run("systemctl start nginx")

def make_selfsigned(domain="bing.com"):
    """生成自签证书，返回 (cert, key)"""
    SSL_DIR.mkdir(parents=True, exist_ok=True)
    cert = str(SSL_DIR / f"{domain}.crt")
    key  = str(SSL_DIR / f"{domain}.key")
    info(f"生成自签证书 CN={domain}...")
    ec = str(SSL_DIR / "ec_param.pem")
    run(f"openssl ecparam -name prime256v1 -out {ec}", check=True)
    run(f'openssl req -x509 -nodes -newkey ec:{ec} '
        f'-keyout {key} -out {cert} -subj "/CN={domain}" -days 3650', check=True)
    os.chmod(cert, 0o644); os.chmod(key, 0o644)
    ok("自签证书生成完成")
    return cert, key

def cert_wizard(service_name=""):
    """
    交互式证书向导
    返回 (cert, key, sni, insecure_flag)
    """
    banner(f"证书配置{' — ' + service_name if service_name else ''}")
    print("1. 使用域名申请 Let's Encrypt 正式证书（推荐，需要域名解析到此 IP）")
    print("2. 使用自签证书（无需域名）")
    while True:
        c = input("请选择 [1/2]：").strip()
        if c == "1":
            domain = input("请输入域名（如 hy2.xiexie25.com）：").strip()
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
                err("域名格式无效"); continue
            result = get_letsencrypt(domain)
            if result:
                ok("使用 Let's Encrypt 正式证书")
                return result[0], result[1], domain, ""
            warn("申请失败，自动降级为自签证书")
            cert, key = make_selfsigned()
            return cert, key, "bing.com", "&insecure=1"
        elif c == "2":
            fake = input("伪装域名（回车默认 bing.com）：").strip() or "bing.com"
            cert, key = make_selfsigned(fake)
            return cert, key, fake, "&insecure=1"
        else:
            print("请输入 1 或 2")

# ══════════════════════════════════════════
#  VLESS 模块
# ══════════════════════════════════════════
def install_xray():
    info("安装/更新 Xray-core（官方脚本）...")
    run('bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install',
        check=True)
    ok("Xray-core 安装完成")

def configure_vless():
    banner("VLESS + XTLS-Vision + Reality 配置")

    # 端口
def configure_vless():
    banner("VLESS + XTLS-Vision + Reality 配置")

    # 端口（让用户自己选）
    port = validate_port("监听端口", default=443)
    r = run(f"ss -tlnp | grep ':{port}'", capture_output=True)
    if r.returncode == 0:
        warn(f"{port} 端口已被占用")
        port = validate_port("请换一个端口", default=8443)

    # 生成密钥
    info("生成 Reality 密钥对...")
    kp = run(f"{XRAY_BIN} x25519", capture_output=True, text=True)
    priv_key = pub_key = ""
    for line in kp.stdout.splitlines():
        if "Private" in line: priv_key = line.split()[-1]
        if "Public"  in line: pub_key  = line.split()[-1]

    uuid_r = run(f"{XRAY_BIN} uuid", capture_output=True, text=True)
    uuid   = uuid_r.stdout.strip()
    short_id = secrets.token_hex(8)

    # 伪装目标
    dest = input("Reality 伪装目标（回车默认 www.microsoft.com:443）：").strip() or "www.microsoft.com:443"
    sni  = dest.split(":")[0]

    # 写配置
    XRAY_CFG.parent.mkdir(parents=True, exist_ok=True)
    cfg = {
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": uuid, "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": dest,
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": priv_key,
                    "shortIds": [short_id]
                }
            },
            "sniffing": {"enabled": True, "destOverride": ["http","tls","quic"]}
        }],
        "outbounds": [{"protocol": "freedom"}]
    }
    XRAY_CFG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    ok("Xray 配置文件已写入")

    run(f"systemctl enable --now {XRAY_SVC}")
    run(f"systemctl restart {XRAY_SVC}")
    time.sleep(1)

    ip   = get_public_ip()
    link = (f"vless://{uuid}@{ip}:{port}"
            f"?encryption=none&flow=xtls-rprx-vision&security=reality"
            f"&sni={sni}&fp=chrome&pbk={pub_key}&sid={short_id}&type=tcp"
            f"&headerType=none#VLESS-Reality")

    VLESS_LINK.write_text(
        f"VLESS+XTLS-Vision+Reality 配置\n"
        f"{'─'*40}\n"
        f"IP       : {ip}\n"
        f"端口     : {port}\n"
        f"UUID     : {uuid}\n"
        f"PublicKey: {pub_key}\n"
        f"ShortId  : {short_id}\n"
        f"SNI      : {sni}\n"
        f"{'─'*40}\n"
        f"链接: {link}\n"
    )

    _print_link("VLESS", link, VLESS_LINK)
    return True

# ══════════════════════════════════════════
#  Hysteria2 模块
# ══════════════════════════════════════════
def install_hy2():
    info("安装/更新 Hysteria2（官方脚本）...")
    run("bash <(curl -fsSL https://get.hy2.sh/)", check=True)
    ok("Hysteria2 安装完成")

def configure_hy2():
    banner("Hysteria2 配置")

    port     = validate_port("监听端口", default=443)
    password = input("连接密码（回车自动生成）：").strip() or rand_pass()
    info(f"密码：{password}")
    masq_url = input("伪装目标 URL（回车默认 https://www.bing.com）：").strip() \
               or "https://www.bing.com"

    cert, key, sni, insecure = cert_wizard("Hysteria2")

    HY2_CFG.parent.mkdir(parents=True, exist_ok=True)
    HY2_CFG.write_text(f"""\
listen: :{port}

tls:
  cert: {cert}
  key: {key}

auth:
  type: password
  password: {password}

masquerade:
  type: proxy
  proxy:
    url: {masq_url}
    rewriteHost: true

ignoreClientBandwidth: false

sniff:
  enable: true
  timeout: 2s
  rewriteDomain: false
  tcpPorts: 80,443,8000-9000
  udpPorts: all
""")
    ok("Hysteria2 配置文件已写入")

    run(f"systemctl enable --now {HY2_SVC}")
    run(f"systemctl restart {HY2_SVC}")
    time.sleep(1)

    ip      = get_public_ip()
    enc_pwd = urllib.parse.quote(password)
    link    = f"hysteria2://{enc_pwd}@{ip}:{port}?sni={sni}{insecure}#HY2-Server"

    HY2_LINK.write_text(f"Hysteria2 配置\n{'─'*40}\nIP  : {ip}\n端口: {port}\n密码: {password}\nSNI : {sni}\n{'─'*40}\n链接: {link}\n")
    _print_link("Hysteria2", link, HY2_LINK)
    return True

# ══════════════════════════════════════════
#  一键部署两个
# ══════════════════════════════════════════
def deploy_all():
    banner("一键部署 VLESS + Hysteria2")
    print("将依次安装并配置 VLESS（Xray）和 Hysteria2\n")

    # ── VLESS ──
    info("第 1 步：安装 Xray-core")
    install_xray()
    info("第 2 步：配置 VLESS")
    configure_vless()

    print()

    # ── HY2 ──
    info("第 3 步：安装 Hysteria2")
    install_hy2()
    info("第 4 步：配置 Hysteria2")
    configure_hy2()

    print()
    banner("部署完成")
    print(f"VLESS  状态：{svc_status_str(XRAY_SVC)}")
    print(f"HY2    状态：{svc_status_str(HY2_SVC)}")
    print(f"\n连接信息已保存：\n  {VLESS_LINK}\n  {HY2_LINK}")

# ══════════════════════════════════════════
#  重启服务
# ══════════════════════════════════════════
def restart_services():
    banner("重启服务")
    run(f"systemctl restart {XRAY_SVC}")
    time.sleep(1)
    run(f"systemctl restart {HY2_SVC}")
    time.sleep(1)
    print()
    print(f"  VLESS    {svc_status_str(XRAY_SVC)}")
    print(f"  HY2      {svc_status_str(HY2_SVC)}")

# ══════════════════════════════════════════
#  工具
# ══════════════════════════════════════════
def _print_link(label, link, filepath):
    print(f"\n{GREEN}{'─'*52}")
    print(f"  {label} 连接链接")
    print(f"{'─'*52}{RESET}")
    print(f"\n{CYAN}{link}{RESET}\n")
    if shutil.which("qrencode"):
        run(f'echo {urllib.parse.quote(link, safe="")} | qrencode -t ANSI256 -o -')
    print(f"已保存至：{filepath}")

def show_links():
    banner("当前连接信息")
    for f, label in [(VLESS_LINK, "VLESS"), (HY2_LINK, "Hysteria2")]:
        if Path(f).exists():
            print(f"\n{CYAN}{label}:{RESET}")
            print(Path(f).read_text())
        else:
            warn(f"{label} 链接未找到（请先配置）")

def enable_bbr():
    banner("开启 BBR 拥塞控制")
    current = run("sysctl net.ipv4.tcp_congestion_control",
                  capture_output=True, text=True).stdout.strip()
    info(f"当前算法：{current}")
    if "bbr" in current:
        ok("BBR 已经是开启状态，无需重复操作")
        return
    c = input("确认开启 BBR？[y/n]：").strip().lower()
    if c != "y":
        warn("已取消")
        return
    sysctl = Path("/etc/sysctl.conf").read_text()
    if "default_qdisc=fq" not in sysctl:
        run('echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf')
    if "tcp_congestion_control=bbr" not in sysctl:
        run('echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf')
    run("sysctl -p", capture_output=True)
    result = run("sysctl net.ipv4.tcp_congestion_control",
                 capture_output=True, text=True).stdout.strip()
    if "bbr" in result:
        ok(f"BBR 开启成功：{result}")
    else:
        err("BBR 开启失败，请检查内核版本（需要 4.9+）")

def uninstall_menu():
    banner("卸载")
    print("1. 卸载 VLESS（Xray）")
    print("2. 卸载 Hysteria2")
    print("3. 全部卸载")
    print("0. 返回")
    c = input("请选择：").strip()

    def do_xray():
        run('bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove')
        VLESS_LINK.unlink(missing_ok=True)
        ok("Xray 已卸载")

    def do_hy2():
        run("bash <(curl -fsSL https://get.hy2.sh/) --remove")
        shutil.rmtree("/etc/hysteria", ignore_errors=True)
        ok("Hysteria2 已卸载")

    if c == "1":
        if input("确认卸载 Xray？[y/n]：").lower() == "y": do_xray()
    elif c == "2":
        if input("确认卸载 Hysteria2？[y/n]：").lower() == "y": do_hy2()
    elif c == "3":
        if input("确认全部卸载？[y/n]：").lower() == "y":
            do_xray(); do_hy2()
            run("crontab -l 2>/dev/null | grep -v certbot | crontab -")

# ══════════════════════════════════════════
#  主菜单
# ══════════════════════════════════════════
def main():
    require_root()
    while True:
        os.system("clear")
        vless_s = svc_status_str(XRAY_SVC)
        hy2_s   = svc_status_str(HY2_SVC)

        print(f"{BOLD}{CYAN}")
        print("╔════════════════════════════════════╗")
        print("║   VH2 — VLESS + Hysteria2 管理     ║")
        print("║   github.com/JoongDa/Vless-Hy2_Deploy  ║")
        print("╚════════════════════════════════════╝")
        print(f"{RESET}")
        print(f"  VLESS    {vless_s}")
        print(f"  HY2      {hy2_s}")
        print()
        print("  ┌─────────────────────────────────┐")
        print("  │  1. 一键部署 VLESS + HY2         │")
        print("  │  2. 仅部署 VLESS                 │")
        print("  │  3. 仅部署 Hysteria2             │")
        print("  │  4. 重启服务                     │")
        print("  │  5. 查看配置                     │")
        print("  │  6. 开启 BBR                     │")
        print("  │  7. 卸载                         │")
        print("  │  0. 退出                         │")
        print("  └─────────────────────────────────┘")

        c = input("\n请选择：").strip()
        os.system("clear")

        if c == "1":
            deploy_all();                        press_enter()
        elif c == "2":
            install_xray(); configure_vless();   press_enter()
        elif c == "3":
            install_hy2();  configure_hy2();     press_enter()
        elif c == "4":
            restart_services();                  press_enter()
        elif c == "5":
            show_links();                        press_enter()
        elif c == "6":
            enable_bbr();                        press_enter()
        elif c == "7":
            uninstall_menu();                    press_enter()
        elif c == "0":
            print("已退出"); sys.exit()
        else:
            print("输入错误"); time.sleep(1)

if __name__ == "__main__":
    main()
