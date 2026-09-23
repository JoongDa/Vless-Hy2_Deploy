# VH2 — VLESS Reality + Hysteria2 部署管理

面向 Debian / Ubuntu VPS 的交互式单文件管理脚本。可单独部署 VLESS Reality 或 Hysteria2，也可依次部署两者。

## 环境与运行

- Linux、systemd、root 权限，Python **3.8+**。
- 建议使用 Ubuntu 22.04 / 24.04 或 Debian 12 / 13；实际兼容性还取决于所选内核版本。
- 缺少的 curl、OpenSSL、iproute2、python3-yaml 会通过 apt 安装。
- 不更换 Linux 内核，不自动修改 GCP 防火墙，不停止现有网站。
- 使用系统 Python，避免虚拟环境无法加载 apt 安装的 PyYAML。

```bash
sudo /usr/bin/python3 VH2.py
```

获取仓库版本：

```bash
curl -fL https://raw.githubusercontent.com/JoongDa/Vless-Hy2_Deploy/main/VH2.py -o VH2.py
sudo /usr/bin/python3 VH2.py
```

测试本地修改时，应先上传修改后的 `VH2.py`，而不是重新下载尚未更新的 `main`。例如从 Windows PowerShell 使用 Google Cloud CLI：

```powershell
gcloud compute scp "C:\Code\VS\VH2D\VH2.py" INSTANCE_NAME:~/VH2.py --zone=ZONE
gcloud compute ssh INSTANCE_NAME --zone=ZONE
```

将 `INSTANCE_NAME`、`ZONE` 替换为自己的实例名与可用区；若使用 IAP，在两个命令后添加 `--tunnel-through-iap`。

## 菜单

```text
1. 安装/更新
2. 卸载
3. 配置
4. 服务管理
0. 退出
```

沿用旧 hy2 的四项主菜单；需要时在子菜单选择 HY2、VLESS 或双协议。配置子菜单包含查看、一键修改、一键导出、性能优化与采样；服务管理包含状态/版本、启动、停止、重启和日志。

首次交互运行会调用 `agree_treaty()`，同意后才安装依赖。记录保存在 `/etc/hy2config/agree.txt`，兼容旧脚本的同名记录；拒绝则退出。诊断、导出、性能采样以及证书续期命令不弹出交互条款，避免阻塞自动续期。

- **部署**：已安装的内核直接进入配置；不会为了重配而先升级。
- **修改配置**：HY2 密码回车保留；VLESS UUID、Reality 私钥和 short ID 默认保留。明确选择重新生成身份后才会改变 VLESS 凭据。
- **升级内核**：支持最新稳定版或指定版本，备份旧程序与配置，恢复配置后重启验证。配置修改与升级分开。
- **双协议部署**：按协议分别提交；第二个协议失败时，已成功部署的第一个协议保留。
- **卸载**：只处理新版 VH2 已管理的节点。停止并禁用服务、删除对应程序、清理本工具跳跃规则、服务性能 drop-in 和导出记录；**保留配置、证书、主服务单元和备份供恢复**。不删除 `/etc/ssl/private`，不清空系统防火墙。全局网络性能参数保留，避免影响其他程序。

## 首次在 Google Cloud VPS 上验证

1. 使用实例的**外部 IP**作为客户端地址。GCP 常见的外部 IPv4 由平台映射到内网地址，不需要把外部 IPv4 配在 Linux 网卡上。自动检测后仍需确认；WARP 出口地址不能当作入站地址。
2. 在实例所属 VPC 创建入站允许规则，确认规则的**目标网络标签**确实加到了该实例。默认配置需要 `tcp:443` 和 `udp:443`；这是两个不同的协议，可以共用端口号。
3. 使用 ACME HTTP 时额外放行 `tcp:80`，域名 A/AAAA 记录须对应实际可达的地址。DNS 验证不需要开放验证端口。
4. 先不开混淆或端口跳跃；部署后用分享链接导入客户端并实际访问网站。
5. 执行下面的诊断命令，再重启 VPS 验证开机启动。确认基础连接正常后再逐项启用高级功能。

```bash
sudo /usr/bin/python3 VH2.py --diagnose
sudo /usr/bin/python3 VH2.py --diagnose --logs
```

VPC 规则不能代替 UFW / nftables 等主机防火墙规则。限制来源时填写实际客户端公网网段；若需要任意 IPv4 客户端连接才使用 `0.0.0.0/0`。IPv6 需要实例/VPC 已配置外部 IPv6、相应客户端链路和独立来源规则；脚本不会为实例开通 IPv6。

参考：[GCP 防火墙操作](https://docs.cloud.google.com/firewall/docs/using-firewalls)、[网络标签](https://docs.cloud.google.com/vpc/docs/add-remove-network-tags)。

## 证书

| 方式 | 要求 | 续期 |
|---|---|---|
| HY2 内置 ACME HTTP | 域名指向实例，TCP 80 可达且未被其他进程占用 | HY2 管理；保持验证路径可达 |
| HY2 内置 ACME Cloudflare DNS | 域名由 Cloudflare DNS 管理，输入对应 Zone 的 API Token | HY2 管理，无需开放 80 |
| 自签 | 无需自有域名 | 有效期 365 天，到期前重新配置 |
| 手动证书路径 | 有效证书、匹配私钥、证书域名匹配 | 由外部证书工具负责，刷新副本 |
| 保留现有 | 接管已有节点 | 保留原证书来源与模式 |

自签模式的通用链接带 `insecure=1`，不能验证服务器身份；有域名时优先使用正式证书。ACME 失败会恢复旧配置，不自动降级为自签。

自签、手动和接管的旧版证书统一安装到以下固定位置（官方服务的组为 `hysteria`）：

```text
/etc/hysteria                    root:hysteria 750
/etc/hysteria/certs              root:hysteria 750
/etc/hysteria/certs/server.crt   root:hysteria 644
/etc/hysteria/certs/server.key   root:hysteria 640
```

证书先在临时目录生成并由 root 校验；备份旧证书后才替换固定文件。启动或后续提交失败时，旧证书、配置及已有目录权限一起恢复。不会放宽 `/etc/ssl/private` 或源证书权限。

预检不再使用 `runuser`，也不启动临时 HY2 进程占用 443；HY2 正式运行交给 systemd 的 `User=hysteria` 及官方服务的 capabilities。脚本会拒绝把 HY2 配置应用到 root 身份的服务。此前代码中的 `runuser` 实际用于 `test -r` 可读性检查；此前随机证书目录是 `/etc/hysteria/vh2-certs/`，因此 `/etc/ssl/private/bing.com.*` 不存在本身不代表生成失败。

遇到此前的部署失败，将本地新版脚本上传 VPS，进入 **3. 配置 → 2. 配置一键修改 → 1. HY2**，重新选择自签或有效证书。已有程序无需卸载重装。部署成功后执行下面的只读检查：

```bash
sudo stat -c '%U:%G %a %n' /etc/hysteria /etc/hysteria/certs /etc/hysteria/certs/server.crt /etc/hysteria/certs/server.key
sudo systemctl show hysteria-server.service -p User -p Group -p AmbientCapabilities -p CapabilityBoundingSet -p ActiveState
sudo ss -lunp 'sport = :443'
```

内置 ACME 模式由 HY2 管理证书，不使用上述固定证书对。

手动证书模式安装独立的 Certbot deploy hook `/etc/letsencrypt/renewal-hooks/deploy/90-vh2`，仅刷新与本节点匹配的证书来源。已有 Certbot 续期计划仍须正常工作。旧版 VH2 的整行匹配 cron 会在可用的 `certbot.timer` 接替后移除；没有该 timer 时会保留并提示，不会误删其他网站的续期计划。

其他证书工具续期后运行：

```bash
sudo /usr/bin/python3 VH2.py --refresh-cert
```

刷新不会打印节点密码。HY2 停止时不会自动将它启动；启动后再刷新。安装在 `/usr/local/lib/vh2/VH2.py` 的 helper 是当次管理脚本的副本，下次成功配置会更新。

参考：[HY2 ACME 配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)、[Cloudflare DNS 配置](https://v2.hysteria.network/docs/advanced/ACME-DNS-Config/)。

## 配置应用与回滚边界

每次配置前，明确列出的文件会备份到 `/var/lib/vh2/backups/<时间-随机值>/`。目录中的 `manifest.json` 记录原路径、权限、属主和对应备份文件名；备份仅 root 可读。

应用顺序：输入校验 → 备份 → 生成候选配置 → 校验 → 原子替换配置 → 重启 → 连续三次确认服务运行且实际 PID 监听目标端口 → 保存状态与导出。

- Xray 使用真实 `xray run -test -config` 校验。
- HY2 先由 root 检查配置字段、证书匹配和有效期，再设置服务专用目录/文件权限。官方没有独立 `server --check` 命令，实际通过 systemd 启动后验证；ACME 最多等待约 150 秒。
- 启动、导出或后续文件写入失败，会恢复已备份文件和原服务启用/运行状态。配置预检失败不会停止原服务。
- 旧版 YAML 可读取；常用自定义字段会保留。当前向导管理单用户，遇到不兼容认证、多用户配置会拒绝自动接管。
- 回滚涵盖管理文件与升级时备份的程序/服务文件，**不撤销 apt 安装、官方安装器修改的所有辅助文件、ACME 已签发证书或外部 DNS 操作**。
- 新证书校验失败不覆盖现有证书。升级前的随机证书目录和备份不会自动清理；新流程只管理固定证书对。
- 自动恢复本身若失败，会输出备份路径。可根据 manifest 将对应文件恢复到记录路径，然后 `systemctl daemon-reload` 并重启对应服务；先阅读 manifest，不要盲目批量覆盖。
- SIGINT 会触发回滚；断电、SIGKILL 和磁盘损坏不保证自动恢复。文件原子写入不等于跨文件断电事务。
- 本机健康检查不能证明 GCP 公网防火墙、域名链路、客户端认证或真实流量通过；这些必须在 VPS 上验证。

## 本地客户端导出

文件都在本机生成，不调用第三方订阅转换服务：

```text
/etc/hy2config/hy2_url_scheme.txt
/etc/hy2config/vless_url_scheme.txt
/etc/hy2config/links.txt
/etc/hy2config/clash.yaml
/etc/hy2config/mihomo.json
/etc/hy2config/sing-box.json
/etc/hy2config/surge.conf
/etc/hy2config/sing-box.yaml   # 兼容旧文件名，内容与 sing-box.json 相同
/etc/hy2config/surge.yaml      # 兼容旧文件名，内容与 surge.conf 相同
```

输出目录与旧脚本一致，目录权限 `700`、导出文件 `600`。成功配置后自动导出，也可选择 **3. 配置 → 3. 一键导出配置/链接**。新旧文件名使用同一份节点状态生成，安装后的自动导出、菜单导出和 `--export` 内容一致。旧版本在其他目录生成的文件保留但不再更新，后续请使用这个统一目录。

通过 `sudo` 执行时，生成的上述配置和链接还会按原文件名额外复制到 `SUDO_USER` 对应用户的 Home 目录（从系统用户记录查询），副本 owner/group 设置为该用户，权限为 `600`，可直接通过 SSH/SCP 下载。再次导出会更新同名副本；`/etc/hy2config/` 下的原文件及权限保持不变。直接以 root 执行、未设置 `SUDO_USER` 时会提示并跳过 Home 副本；复制失败也不影响原配置生成。

旧脚本的 `.yaml` 文件名并不代表客户端实际接受 YAML：sing-box 应导入 `.json`，Surge 应导入 `.conf`。本地导出不附加第三方规则订阅，避免依赖转换站和不明远程规则。

Mihomo 和 sing-box 文件为最小可运行配置，监听本机混合代理端口 `7890`（不允许局域网访问），通过选择器切换节点；不是 TUN、分流规则订阅或系统代理自动设置。不要同时让两个客户端绑定这个端口。其他客户端优先使用单节点链接导入。

Surge 模板仅导出 HY2，包含 TLS、跳跃及可用的 Salamander 参数；不填未经测速的带宽值。请使用支持所需功能的客户端版本，尤其 Salamander 的平台限制，见 [Surge 官方 HY2 文档](https://manual.nssurge.com/policies/hysteria2.html)。没有 HY2，或凭据包含无法可靠转义的引号、反斜杠、控制字符时，模板会写明原因并设为拒绝流量；Mihomo、sing-box 和链接仍正常导出。Surge 模板未在真实客户端上完成导入验证。

包含混淆或跳跃时自动同步导出参数；sing-box 跳跃字段要求 **1.11+**。安装 `qrencode` 后会显示二维码；二维码内容是原始分享链接。所有导出文件包含连接凭据，只应传给自己的客户端。

```bash
sudo /usr/bin/python3 VH2.py --export
```

导出依据 `/var/lib/vh2/state.json`；绕过向导手动修改配置后，应重新进入配置向导同步状态。不要将状态文件、DNS Token、链接或私钥上传到公开仓库。

## 高级选项

| 选项 | 原理与用途 | 低配 VPS 建议 |
|---|---|---|
| 协议嗅探 | 解析 HTTP Host / TLS SNI 等信息，从连接中提取目标域名，供域名规则等使用；不是解密 HTTPS | 没有域名分流需求就关闭，省去解析工作和可能的等待 |
| 带宽策略 | 不提供带宽时，HY2 默认采用自适应 QUIC BBR；提供带宽可参与选择 Brutal。Brutal 按指定速率发送，丢包时补偿发送 | 初始不指定虚构带宽；`ignoreClientBandwidth=false` 允许客户端提示，并不强制 Brutal |
| Salamander 混淆 | 把协议数据包变换为随机字节外观，应对特定 QUIC 识别/阻断；需要两端同密码 | 默认关闭；有实际阻断再启用。增加处理工作且失去标准 HTTP/3 伪装 |
| 端口跳跃 | 客户端周期性更换 UDP 目标端口，服务端把范围内端口重定向到实际监听端口 | 仅针对单端口干扰/限制；不是多端口带宽叠加，默认关闭 |
| 系统 TCP BBR | 按估计带宽和最小 RTT 调整 TCP 发送，试图减少过长排队 | 内核支持时自动启用；不会直接切换 HY2 的 QUIC 控制器 |

- **嗅探**：默认新节点关闭，可按需要启用。
- **带宽策略**：`ignoreClientBandwidth=true` 忽略客户端带宽提示，使用非 Brutal 控制器。设定不可能达到的带宽可能增加丢包、CPU 负担和流量消耗。
- **Salamander 混淆**：需要客户端使用相同密码，启用后不再支持标准 HTTP/3 伪装。
- **端口跳跃**：使用专用 `inet vh2_hopping` nftables 表和 `vh2-hopping.service`，同时处理本地入站 IPv4/IPv6 UDP。只重建自己的表，不保存或恢复整套防火墙。关闭时精确删除自己的规则。云防火墙额外放行跳跃范围，主机防火墙还需允许重定向后的服务端口。其他防火墙管理器若执行全局 flush，需执行 `systemctl restart vh2-hopping` 恢复该表。
- **TCP BBR**：验证内核支持后写入独立 `/etc/sysctl.d/90-vh2-bbr.conf`，失败恢复；不会更换内核，也不会直接改变 HY2 的 QUIC 算法。卸载节点不会撤销全局 TCP 设置。

## 免费 Google Cloud VPS 的性能默认值

免费配额通常使用 `e2-micro`：标准机型为 1 GB 内存、2 个可见 vCPU，但持续算力份额合计约 **0.25 vCPU**。突发可短时使用更多 CPU；把系统里看到的“2 核”当作两颗专用核心会高估持续吞吐。最大网络带宽也不代表代理必定能达到的速度。

脚本在每次配置应用时自动读取内存和可见 CPU；还会考虑可读取的 cgroup v2 内存上限。它不根据 CPU 数量设置线程限制，也不能探测/解除 Google 宿主机的实际调度配额。

| 自动设置 | e2-micro 默认策略 | 理由 |
|---|---|---|
| UDP socket 缓冲区上限 | `rmem_max` / `wmem_max` 至少 16 MiB | 允许 QUIC 申请较大缓冲，减少应用来不及读取时的内核丢包 |
| 更小机器 | 有效内存 <512 MiB 时目标为 8 MiB | 本脚本的保守策略；不是经过实测得到的最优值 |
| 已有更大上限 | 保留，不降低 | 避免覆盖管理员已经做过的资源调整 |
| TCP 拥塞控制 | 支持则 BBR，不支持保留原算法 | 改善适合 BBR 的 TCP 传输，不安装第三方内核 |
| 默认队列 | 配合 TCP BBR 设置 `fq` 默认值 | 不执行 `tc` 替换正在使用的网卡队列；已有网卡队列不一定立即改变，重启后再检查 |
| 进程优先级 | 普通调度 `Nice=-5`，已有更高优先级保留 | 争用时适度优先处理代理流量；不采用实时调度，不绕过 CPU 配额 |
| QUIC 窗口 | 保留官方默认 8 MiB/流、20 MiB/连接上限 | 大窗口会增加潜在内存需求，未测出窗口瓶颈前不放大 |
| QUIC MTU 发现 | 新配置启用默认自动发现 | 尽可能用合适大小的数据包，减少单位流量的包处理次数 |
| 嗅探、混淆、跳跃 | 新配置默认关闭 | 减少不需要的工作；旧节点的显式设置保留 |

缓冲区**上限不是预分配量**；实际内存由应用、流量和连接数量共同决定。不会把所有 socket 的默认缓冲区改成 16 MiB，也不会把 QUIC 窗口扩大到数百 MiB。保留 Go 默认 GC/并发配置和内核的 GSO 自动探测，不禁用加密、不关闭安全隔离、不创建“加速 swap”。

自动设置保存在 `/etc/sysctl.d/91-vh2-performance.conf` 和各服务的 `90-vh2-performance.conf` drop-in，随配置一起备份；应用或启动失败时恢复文件及已修改 sysctl 的原值。加载 BBR 模块本身不会在回滚时卸载。

VLESS 使用 TCP，HY2 使用用户态 QUIC。前者在 CPU 紧张且线路顺畅时通常值得优先测试；后者可能在丢包线路上表现更好。请在**相同客户端、目标和时段**分别传输 1–2 分钟，比较进入持续阶段后的速度、延迟与 CPU，不能用一次短测速确定优劣。

传输过程中另开 SSH 窗口：

```bash
sudo /usr/bin/python3 VH2.py --performance-report
```

此命令采样 5 秒，显示系统 CPU 忙碌/steal、内存、UDP 缓冲区错误增量和服务资源设置，不自行下载测速文件。UDP 计数器覆盖整个系统；steal 高表示虚拟 CPU 等待宿主机调度，但 steal 低也不证明没有共享 CPU 限制。采样期间没有实际传输，不能用来判断满载性能。

实际吞吐受客户端、线路、CPU、流控窗口等共同限制。粗略理解接收窗口：`窗口需求 ≈ 吞吐率 × RTT`，100 Mbps、200 ms 约对应 2.5 MB 在途数据；增加窗口只有在窗口确实限制吞吐时才有价值，还要考虑流向、并发流和客户端窗口。

来源：[Google E2 共享核心](https://docs.cloud.google.com/compute/docs/general-purpose-machines#e2_shared-core)、[HY2 性能建议](https://v2.hysteria.network/docs/advanced/Performance/)、[quic-go 的缓冲区/GSO/MTU 说明](https://quic-go.net/docs/quic/optimizations/)。这些默认值是可验证的起点，**没有承诺固定提速百分比或“压满 1 Gbps”**。

## 开发验证

```bash
python3 -m pip install PyYAML
python3 -m unittest discover -s tests -v
python3 -m py_compile VH2.py
```

测试通过临时目录和模拟系统命令验证密码转义、URI/二维码、身份保留、首次部署、升级、失败/中断回滚、统一导出、固定证书替换、菜单、首次同意及防火墙清理。OpenSSL 证书配对测试使用真实 OpenSSL；POSIX 权限断言仅在 Linux 等支持的平台执行。测试不会修改宿主机 systemd 或防火墙，也不能替代目标 VPS 的部署与公网连接测试。
