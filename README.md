# VLESS + XTLS-Vision + Reality 一键部署

一键在 Linux VPS 上部署 VLESS + XTLS-Vision + Reality 代理节点。  
自动安装 Xray-core、生成密钥对、写入配置、启动服务，并输出可直接导入客户端的 `vless://` 分享链接。

---

## 适用系统

- Ubuntu 20.04 / 22.04 / 24.04
- Debian 11 / 12

---

## 特性

- 自动检测 443 端口占用，被占用时自动切换到 8443
- 自动生成 UUID、Reality 密钥对、随机 ShortId
- 配置文件保存至 `/root/reality_config.txt`
- 输出 `vless://` 分享链接，一键导入客户端

---

## 使用方法

```bash
# 下载脚本
wget https://raw.githubusercontent.com/JoongDa/vless-xtls-reality-deploy/main/vless_xtls_reality.py

# 以 root 权限运行
sudo python3 vless_xtls_reality.py
```

运行完成后终端会输出 `vless://` 链接，复制到客户端导入即可。

---

## 部署完成后

配置信息保存在服务器的 `/root/reality_config.txt`，包含：

```
IP、端口、UUID、Public Key、Private Key、Short ID、VLESS 链接
```

---

## 防火墙

脚本使用 443 端口（被占用时自动切换 8443），需在云服务商控制台放行对应 TCP 端口：

| 云服务商 | 操作路径 |
|----------|----------|
| GCP | VPC 网络 → 防火墙规则 → 创建入站规则 |
| AWS | EC2 → 安全组 → 入站规则 |
| Oracle | 网络 → 安全列表 → 入站规则 |
| Vultr / Hetzner | 无需操作，默认开放 |

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
- curl（用于安装 Xray，系统自带）
- Xray-core（脚本自动安装）
