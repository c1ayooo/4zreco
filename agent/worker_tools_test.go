package agent

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/hosttools"
)

// worker 的 system prompt 里必须带宿主工具清单。
//
// 回归背景：工具清单原本只进 planner 的唤醒提示（用于「派意图选手段」），
// 而真正动手的 worker 看不到它——实测新装的一批工具（dalfox/feroxbuster/
// chisel/gitleaks…）一次都没被用起来，agent 只会 python3 + curl + ssh。
func TestWorkerSystemIncludesHostTools(t *testing.T) {
	sys := workerSystem("127.0.0.1:8788", "", "/opt/4zreco/data", "/tmp/run")
	if !strings.Contains(sys, "本机可用工具") {
		t.Fatal("worker 的 system prompt 里应注入宿主工具清单")
	}
}

// 清单不能把 prompt 撑爆——它每次 worker run 都在 system prompt 里。
func TestWorkerToolListStaysCompact(t *testing.T) {
	txt := hosttools.SummaryText()
	if txt == "" {
		t.Skip("本机没有可用工具,跳过体积断言")
	}
	if len(txt) > 4000 {
		t.Errorf("工具清单 %d 字节,太大（每轮都进 system prompt）", len(txt))
	}
	// 每行都要带用途
	for _, line := range strings.Split(txt, "\n") {
		if !strings.HasPrefix(line, "✓ ") {
			continue
		}
		if !strings.Contains(line, "——") {
			t.Errorf("可用项应带用途: %q", line)
		}
	}
}

// mainagent 也有 Bash 工具、会自己动手查证，所以同样需要工具清单。
func TestMainAgentSystemIncludesHostTools(t *testing.T) {
	sys := mainAgentSystem("拿下目标", "/opt/4zreco/data", "/tmp/run")
	if !strings.Contains(sys, "本机可用工具") {
		t.Fatal("mainagent 的 system prompt 里应注入宿主工具清单")
	}
}
