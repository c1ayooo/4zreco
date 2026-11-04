package db

import (
	"regexp"
	"testing"
)

// 内置规则在【真实渗透命令】上的误报率。
//
// 上一版实测：把全部内置规则改成 judge 后，11 次真实调用被规则直接 deny，
// 全部是误报：
//
//	rm -f /tmp_out.$$                       → 命中「删除系统关键目录」（裸 / 分支）
//	for p in /api/.../reboot ...            → 命中「关机 / 重启」（路径里的 reboot）
//	touch /usr/share/nmap/... && rm -f ...  → 命中「删除系统关键目录」
//
// 根因：规则在**原始命令文本**上做正则，而 agent 的正常探测文本里大量出现
// 这些词。规则存在的意义是「把值得研判的调用挑出来交给模型」，不是「自己拍板」；
// 一旦动作是 deny/ask，误报就直接变成任务中断。
//
// 这里把真实命令固定下来当回归基线：这些命令是**合法的渗透动作**，
// 任何「确定性破坏」类规则都不该命中。
func TestBuiltinRulesDoNotFalsePositiveOnRealCommands(t *testing.T) {
	// 从生产环境的拦截历史里取的真实命令（全部是被误拦的合法探测）。
	real := []struct {
		name string
		cmd  string
	}{
		{"临时文件清理", `cd /opt/4zreco/data/tasks/3/i348/ && curl -s -o /tmp_out.$$ "http://10.10.42.18:8161/x"; rm -f /tmp_out.$$`},
		{"设备管理路径枚举", `for p in /getPreLoginData/ /login.cgi /webacs/ /reboot /reset /getVersion; do code=$(curl -s -o /dev/null -w "%{http_code}" "https://172.24.0.14$p"); done`},
		{"清空代理环境", `unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy; curl -sk https://172.16.105.2:9000/`},
		{"REST 路径枚举", `for path in /api/ /api/users /api/login /api/status /api/config /api/health /api/version; do curl -s -o /dev/null -w "%{http_code}" "http://10.10.47.11:6969$path"; done`},
		{"云平台 API 枚举", `for action in GetZones QueryZone CreateVm StartVm StopVm RebootVm DestroyVm; do curl -s "http://10.10.47.11:8080/?Action=$action"; done`},
		{"nmap 脚本目录探测", `touch /usr/share/nmap/scripts/_t.nse 2>&1 && echo WRITABLE && rm -f /usr/share/nmap/scripts/_t.nse`},
		{"端口连通性探测", `for ip in 10.10.70.1 10.10.70.254; do timeout 3 ping -c1 -W1 $ip >/dev/null 2>&1 && echo "$ip up"; done`},
		{"Windows 主机接口探测", `for p in /getPreLoginData/ /login.cgi /webacs/; do curl -s "https://172.24.0.14$p"; done`},
	}

	// 只断言「确定性破坏」类规则：这些规则命中就直接拦下（deny），
	// 误报 = 任务中断。候选筛选类（HTTP 路径枚举类）交给模型研判，
	// 命中不算误报。
	hard := map[string]string{
		"递归强制删除":   `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		"删除系统关键目录": `\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		"清空系统关键目录": `\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		"关机重启":     `(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		"磁盘格式化":     `\bmkfs\b`,
		"磁盘擦除":     `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
		"覆写磁盘":     `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
		"Fork 炸弹":    `:\(\)\s*\{[^}]*:\|:`,
		"杀全部进程":    `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
		"清空防火墙":    `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
	}

	for _, r := range real {
		for name, pat := range hard {
			re, err := regexp.Compile(pat)
			if err != nil {
				t.Fatalf("规则 %q 正则编译失败: %v", name, err)
			}
			if re.MatchString(r.cmd) {
				t.Errorf("规则 %q 在合法命令上误报（片段 %q）：\n  场景=%s\n  cmd=%s",
					name, re.FindString(r.cmd), r.name, r.cmd)
			}
		}
	}
}

// 收窄之后，真正的破坏行为仍然必须被规则抓住——否则就是漏报。
func TestBuiltinRulesStillCatchRealDanger(t *testing.T) {
	hard := map[string]string{
		"递归强制删除":   `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		"删除系统关键目录": `\brm\b[^"'\n]{0,60}["'\s](/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:["'\s]|$|/(?:["'\s]|$)))`,
		"清空系统关键目录": `\brm\b[^"'\n]{0,120}["'\s][^"'\n]{0,80}/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)/\*`,
		"关机重启":     `(?:^|[;&|]\s*|\b(?:sudo|doas)\s+)(?:shutdown|reboot|halt|poweroff)\b|\binit\s+[06]\b`,
		"磁盘格式化":     `\bmkfs\b`,
		"磁盘擦除":     `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
	}
	danger := []struct {
		rule string
		cmd  string
	}{
		{"递归强制删除", `rm -rf /var/www/html`},
		{"递归强制删除", `rm -rf --no-preserve-root /`},
		{"删除系统关键目录", `rm -rf /etc/`},
		{"清空系统关键目录", `rm -rf /var/lib/*`},
		{"清空系统关键目录", `rm -rf /etc/*`},
		{"删除系统关键目录", `rm -rf /usr`},
		{"关机重启", `sudo shutdown -h now`},
		{"关机重启", `reboot`},
		{"关机重启", `cd /tmp && poweroff`},
		{"磁盘格式化", `mkfs.ext4 /dev/sdb1`},
		{"磁盘擦除", `shred -v /dev/sda`},
	}
	for _, d := range danger {
		pat, ok := hard[d.rule]
		if !ok {
			t.Fatalf("未知规则 %q", d.rule)
		}
		re := regexp.MustCompile(pat)
		if !re.MatchString(d.cmd) {
			t.Errorf("规则 %q 漏掉了 %q", d.rule, d.cmd)
		}
	}
}
