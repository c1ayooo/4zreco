package config

import (
	"path/filepath"
	"testing"
)

// TestPathsLayout 锁定目录布局本身：解析器是唯一决策点，这里的期望值就是布局
// 契约——改布局先改 Paths，再改这里。
func TestPathsLayout(t *testing.T) {
	p := Paths{Base: "/opt/4zreco", Data: "/opt/4zreco/data"}

	// Base 派生：随分发物走。
	if got, want := p.JWTKeyPath(), filepath.Join("/opt/4zreco", "jwt.key"); got != want {
		t.Errorf("JWTKeyPath = %s, want %s", got, want)
	}
	if got, want := p.NucleiTemplates(), filepath.Join("/opt/4zreco", "nuclei-templates"); got != want {
		t.Errorf("NucleiTemplates = %s, want %s", got, want)
	}
	if got, want := p.LegacyNucleiTemplates(), filepath.Join("/opt/4zreco/data", "nuclei-templates"); got != want {
		t.Errorf("LegacyNucleiTemplates = %s, want %s", got, want)
	}

	// Data 派生：运行时产物。
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"Traffic", p.Traffic(), "/opt/4zreco/data/traffic"},
		{"Evidence", p.Evidence(), "/opt/4zreco/data/evidence"},
		{"Transcripts", p.Transcripts(), "/opt/4zreco/data/transcripts"},
		{"NoaRoot", p.NoaRoot(), "/opt/4zreco/data/noa"},
		{"HoneypotSignatures", p.HoneypotSignatures(), "/opt/4zreco/data/signatures/honeypot.json"},
		{"DeleteStaging", p.DeleteStaging(), "/opt/4zreco/data/.delete-staging"},
		{"TaskArchivesRoot", p.TaskArchivesRoot(), "/opt/4zreco/data/archives/tasks"},
		{"TaskDir", p.TaskDir("42"), "/opt/4zreco/data/tasks/42"},
		{"TaskUploads", p.TaskUploads("42"), "/opt/4zreco/data/tasks/42/uploads"},
		{"SessionUploads", p.SessionUploads("conv-7"), "/opt/4zreco/data/sessions/conv-7/uploads"},
		{"DraftUploads", p.DraftUploads("d1"), "/opt/4zreco/data/drafts/d1/uploads"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}

	// 布局语义（保护名单）与平台无关，单独锁。
	want := []string{"traffic", "evidence"}
	got := p.ProtectedWorkspaceDirs()
	if len(got) != len(want) {
		t.Fatalf("ProtectedWorkspaceDirs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ProtectedWorkspaceDirs[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

// TestNewPathsAbs 验证相对数据根被绝对化（MITM CA 路径要注入 worker shell，
// 相对路径在别的 CWD 下解析不到，这是历史上真实踩过的坑）。
func TestNewPathsAbs(t *testing.T) {
	p := NewPaths("data")
	if filepath.IsAbs(p.Base) != true {
		t.Errorf("Base 未绝对化: %s", p.Base)
	}
	if filepath.IsAbs(p.Data) != true {
		t.Errorf("Data 未绝对化: %s", p.Data)
	}
}
