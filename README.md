# VH2 — VLESS + Hysteria2 一键部署管理脚本

一键在 Linux VPS 上部署并管理 **VLESS（XTLS-Vision + Reality）** 和 **Hysteria2** 双协议节点。  
自动安装、配置、启动服务，输出可直接导入客户端的分享链接。

---

## 设计理念

两个协议互补，覆盖不同使用场景：

| 协议 | 适合场景 | 传输层 |
|------|---------|--------|
| VLESS + Reality | 大文件下载、高速传输、稳定连接 | TCP |
| Hysteria2 | 日常浏览、低延迟、高丢包网络 | UDP (QUIC) |

---

## 适用系统

- Ubuntu 20.04 / 22.04 / 24.04 / 25.04
- Debian 11 / 12

---

## 使用方法

```bash
# 下载脚本
wget https://raw.githubusercontent.com/JoongDa/Vless-Hy2_Deploy/main/VH2.py

# 以 root 权限运行
sudo python3 VH2.py
```

---

## 功能菜单

```
╔════════════════════════════════════╗
║   VH2 — VLESS + Hysteria2 管理     ║
╚════════════════════════════════════╝
  VLESS    运行中
  HY2      运行中

  ┌─────────────────────────────────┐
  │  1. 一键部署 VLESS + HY2         │
  │  2. 仅部署 VLESS                 │
  │  3. 仅部署 Hysteria2             │
  │  4. 重启服务                     │
  │  5. 查看配置                     │
  │  6. 卸载                         │
  │  0. 退出                         │
  └─────────────────────────────────┘
```

---

## 证书配置

脚本支持两种证书方式，部署时交互选择：

**Let's Encrypt 正式证书（推荐）**
- 输入域名，脚本自动申请
- 客户端无需跳过证书验证
- 自动设置每日续期

**自签证书（无需域名）**
- 无需域名，直接使用 IP
- 自动生成，有效期 10 年
- 客户端需开启 `insecure` 选项

> 申请正式证书失败时自动降级为自签证书。

---

## 部署完成后

配置信息分别保存在：

```
/root/vless_config.txt       # VLESS 链接及详细参数
/etc/hysteria/hy2_link.txt   # Hysteria2 链接
```

---

## 防火墙

脚本默认使用 443 端口（VLESS 被占用时自动切换 8443），需在云服务商控制台放行对应端口：

| 云服务商 | 操作路径 |
|---------|---------|
| GCP | VPC 网络 → 防火墙规则 → 创建入站规则 |
| AWS | EC2 → 安全组 → 入站规则 |
| Oracle | 网络 → 安全列表 → 入站规则 |
| Vultr / Hetzner | 默认开放，无需操作 |

---

## 客户端推荐

| 平台 | 客户端 |
|------|--------|
| Windows / macOS | [Hiddify](https://github.com/hiddify/hiddify-app/releases/latest) |
| Android | [Hiddify](https://github.com/hiddify/hiddify-app/releases/latest) |
| iOS | Shadowrocket |

---

## 依赖

- Python 3.6+（系统自带）
- curl（系统自带）
- Xray-core（脚本自动安装）
- Hysteria2（脚本自动安装）
- certbot（申请正式证书时自动安装）