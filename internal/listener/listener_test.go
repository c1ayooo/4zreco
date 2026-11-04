package listener

import (
	"net"
	"strings"
	"testing"
	"time"
)

// 全生命周期：起监听 → 回连（发送 banner）→ 会话捕获 → 停止。
func TestListenerCatchAndCapture(t *testing.T) {
	m := NewManager()
	if _, err := m.Start("probe", 0); err == nil {
		t.Fatal("端口 0 应被拒绝")
	}
	if _, err := m.Start("test1", 18443); err != nil {
		t.Fatal(err)
	}

	// 回连方：连上并发送 banner，保持连接。
	c, err := net.Dial("tcp", "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("uid=0(root) gid=0(root)\r\n")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var sessions []Session
	for time.Now().Before(deadline) {
		sessions, _ = m.Get("test1")
		if len(sessions) > 0 && sessions[0].Preview != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions=%d，应为 1", len(sessions))
	}
	if !strings.Contains(sessions[0].Preview, "uid=0(root)") {
		t.Fatalf("preview=%q，应含 banner", sessions[0].Preview)
	}
	if !sessions[0].Open {
		t.Fatal("连接仍打开时 Open 应为 true")
	}

	// 同名重复启动应拒绝。
	if _, err := m.Start("test1", 18446); err == nil {
		t.Fatal("同名监听器应被拒绝")
	}

	final, err := m.Stop("test1")
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 1 {
		t.Fatalf("最终快照 sessions=%d", len(final))
	}
	if _, ok := m.Get("test1"); ok {
		t.Fatal("停止后 Get 应返回 false")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:18443", time.Second); err == nil {
		t.Fatal("停止后端口应已关闭")
	}
}

// 校验：名字/端口越界拒绝。
func TestListenerValidation(t *testing.T) {
	m := NewManager()
	if _, err := m.Start("", 12345); err == nil {
		t.Fatal("空名字应被拒绝")
	}
	if _, err := m.Start("bad name!", 12345); err == nil {
		t.Fatal("非法字符应被拒绝")
	}
	if _, err := m.Start("low", 80); err == nil {
		t.Fatal("低端口应被拒绝")
	}
	if _, err := m.Start("ok", 65536); err == nil {
		t.Fatal("超范围端口应被拒绝")
	}
}
