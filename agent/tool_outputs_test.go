package agent

import (
	"context"
	"strings"
	"testing"
)

// v0.4.29（P0b #2）：证据逐字回验——证据里的有效行必须在本次工具回显中找到出处。
func TestToolOutputLedgerVerifyEvidence(t *testing.T) {
	l := NewToolOutputLedger()
	l.Add("HTTP/1.1 200 OK\nServer: nginx/1.25.3 (Ubuntu)\n\n{\"total\":63631,\"data\":[...]}\nX-Powered-By: PHP/8.1.2")
	l.Add("$ id\nuid=0(root) gid=0(root)")

	// 两行都能逐字找到（含空白差异归一化）。
	ev := "  Server: nginx/1.25.3 (Ubuntu)   \n  \"total\":63631,\"data\":[...]  \nuid=0(root) gid=0(root)"
	matched, total := l.VerifyEvidence(ev)
	if matched != 3 || total != 3 {
		t.Fatalf("matched=%d total=%d want 3/3 (ev=%q)", matched, total, ev)
	}
	if v := evidenceVerdict(matched, total); v != "good" {
		t.Fatalf("verdict=%s want good", v)
	}

	// 全是转述 → none。
	ev = "该接口未授权返回了 6 万多条患者记录，说明存在未授权访问。"
	matched, total = l.VerifyEvidence(ev)
	if matched != 0 || total != 1 { // 单行长句计入但未命中
		t.Fatalf("matched=%d total=%d want 0/1", matched, total)
	}
	if v := evidenceVerdict(matched, total); v != "good" {
		// total<2 视为无法判定 → good（不打扰）
		t.Fatalf("verdict=%s want good for undecidable evidence", v)
	}

	// 两条以上且全无出处 → none。
	ev = "第一条转述结论写在这里支撑漏洞判断。\n第二条转述结论继续描述影响范围。"
	matched, total = l.VerifyEvidence(ev)
	if matched != 0 || total != 2 {
		t.Fatalf("matched=%d total=%d want 0/2", matched, total)
	}
	if v := evidenceVerdict(matched, total); v != "none" {
		t.Fatalf("verdict=%s want none", v)
	}

	// 部分命中 → partial（命中不足一半）。
	ev = "Server: nginx/1.25.3 (Ubuntu)\n这是一条纯转述、工具输出里不存在的内容。\n另一条同样不在工具输出里的补充说明文字。"
	matched, total = l.VerifyEvidence(ev)
	if matched != 1 || total != 3 {
		t.Fatalf("matched=%d total=%d want 1/3", matched, total)
	}
	if v := evidenceVerdict(matched, total); v != "partial" {
		t.Fatalf("verdict=%s want partial", v)
	}

	// 短行（<20 字节）不计入分母。
	matched, total = l.VerifyEvidence("id\nls\n这是一个足够长的转述句子用来测试分母是否忽略短行。")
	if total != 1 {
		t.Fatalf("total=%d want 1 (short lines must be ignored)", total)
	}
}

// ANSI 控制序列不应影响匹配。
func TestToolOutputLedgerANSI(t *testing.T) {
	l := NewToolOutputLedger()
	l.Add("\x1b[31mERROR: access denied for user admin\x1b[0m")
	if matched, total := l.VerifyEvidence("ERROR: access denied for user admin"); matched != 1 || total != 1 {
		t.Fatalf("matched=%d total=%d want 1/1", matched, total)
	}
}

// ctx 挂载/读取。
func TestToolOutputsContext(t *testing.T) {
	l := NewToolOutputLedger()
	ctx := WithToolOutputs(context.Background(), l, EvidenceVerifyBlock)
	got, mode := ToolOutputsFromContext(ctx)
	if got != l || mode != EvidenceVerifyBlock {
		t.Fatalf("got ledger=%p mode=%v", got, mode)
	}
	if led, m := ToolOutputsFromContext(context.Background()); led != nil || m != EvidenceVerifyOff {
		t.Fatalf("empty ctx must yield nil/off, got %v/%v", led, m)
	}
	// 档位解析
	for in, want := range map[string]EvidenceVerifyMode{
		"off": EvidenceVerifyOff, "block": EvidenceVerifyBlock, "warn": EvidenceVerifyWarn,
		"": EvidenceVerifyWarn, "strict": EvidenceVerifyBlock, "0": EvidenceVerifyOff,
	} {
		if got := EvidenceVerifyModeFromString(in); got != want {
			t.Fatalf("mode(%q)=%v want %v", in, got, want)
		}
	}
}

// 台账超出上限时滚动丢弃最旧记录。
func TestToolOutputLedgerRolling(t *testing.T) {
	l := NewToolOutputLedger()
	for i := 0; i < toolOutputLedgerMaxEntries+10; i++ {
		l.Add(strings.Repeat("x", 32))
	}
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n > toolOutputLedgerMaxEntries {
		t.Fatalf("entries=%d must be capped at %d", n, toolOutputLedgerMaxEntries)
	}
}
