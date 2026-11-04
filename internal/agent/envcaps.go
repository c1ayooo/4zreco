package agent

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// envCapNote 是「本进程能干什么特权网络操作」的代码侧说明，追加到 Bash 工具的
// description 上（因此只有真正持有 Bash 的 agent 才会看到它）。放在这里而不是提示词里，
// 是因为它取决于运行形态：Docker 镜像里是 root，systemd 二进制部署下是非 root + 能力位，
// 两种情况下模型该敲的命令不一样。判断全部来自运行时事实（euid + CapEff），不依赖配置。
//
// 之所以值得单独说一句：agent 在旧版沙箱里为了搞清「masscan 为什么报 PF_PACKET not
// supported」「nmap -sS 为什么说需要 root」烧掉了十几轮，最后退回自写 Python 扫描器。
// 这类环境事实一次讲清楚，比让模型反复试探便宜得多。
var (
	envCapOnce sync.Once
	envCapText string
)

// EnvCapabilityNote returns the code-owned environment capability block (empty on
// non-Linux, where the /proc and capability model don't apply).
func EnvCapabilityNote() string {
	envCapOnce.Do(func() { envCapText = buildEnvCapNote() })
	return envCapText
}

// capBit reports whether the effective capability set includes the given CAP_* bit
// number (CAP_NET_RAW=13, CAP_NET_ADMIN=12, CAP_NET_BIND_SERVICE=10 on Linux).
func capBit(caps uint64, bit uint) bool { return caps&(1<<bit) != 0 }

// effectiveCaps parses CapEff out of /proc/self/status (hex, no 0x prefix).
// Returns 0 when unavailable — callers then just describe the degraded case.
func effectiveCaps() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return 0
}

func buildEnvCapNote() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	caps := effectiveCaps()
	root := os.Geteuid() == 0
	raw := root || capBit(caps, 13)   // CAP_NET_RAW
	admin := root || capBit(caps, 12) // CAP_NET_ADMIN
	// 本机面向目标的能力说明。措辞按「先给结论、再给替代方案」写——模型读到的是
	// 当前这台机器的事实，不是建议。
	var b strings.Builder
	b.WriteString("\n\n**本机网络能力**（运行环境事实，直接照此选命令，不要反复试探）：\n")
	switch {
	case root:
		b.WriteString("- 当前进程以 **root** 运行：`nmap -sS/-sU/-O/-PR`、`masscan`、`ping` 等特权扫描可直接用，无需 `--privileged`、无需 sudo。\n")
	case raw && admin:
		b.WriteString("- 当前进程**不是 root**（uid=" + strconv.Itoa(os.Geteuid()) + "），但已授予 CAP_NET_RAW + CAP_NET_ADMIN：raw socket 可用，`masscan`、`ping`、`hping3` 等直接能跑。\n")
		b.WriteString("- **`nmap` 例外**：它按 euid 而不是能力位判断权限，所以 `-sS`/`-sU`/`-O`/`-PR` 这类特权扫描必须**显式加 `--privileged`**（如 `nmap --privileged -sS -Pn -n -p- <target>`）。**不要用 sudo**（没有交互密码，必然卡住）。\n")
	case raw:
		b.WriteString("- 当前进程不是 root，仅授予 CAP_NET_RAW：`masscan`/`ping` 可用；`nmap` 的特权扫描需显式 `--privileged`（它按 euid 判断），且需要 CAP_NET_ADMIN 才能正常发原始包，失败就用 `-sT`。\n")
	default:
		b.WriteString("- 当前进程**无 CAP_NET_RAW**：`masscan`、`nmap -sS`、`nmap -sU`、ARP/`-PR` 扫描**不可用**（会报 PF_PACKET not supported 或 requires root privileges）。\n")
		b.WriteString("- 替代方案：`nmap -sT`（TCP connect 扫描，非特权、结果同样准确，只是慢）、`nmap -sT -sV` 做服务识别。**不要**为了绕过去现写扫描器或尝试 sudo。\n")
	}
	b.WriteString("- `nuclei`、`sqlmap`、`httpx`、`curl` 等不需要特权，直接可用。\n")
	return b.String()
}
