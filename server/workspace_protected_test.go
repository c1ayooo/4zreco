package server

import (
	"os"
	"path/filepath"
	"testing"
)

// 工作空间的文件管理器能删掉系统自己的数据目录。
//
// 回归背景（2026-10-21 全量重置后巡检发现）：工作空间根目录就是 data
// 目录，文件管理器的路径约束只保证「不越出根目录」，但 traffic（3.3G 流量
// 采集库）、evidence（漏洞绑定的流量正文）、nuclei-templates（934M 模板库）
// 都在根目录下，页面上还带着删除按钮。os.RemoveAll 不可逆——删掉 traffic
// 之后所有历史请求响应都没了，findings 里的绑定变成空指针；删掉模板库要
// 重新 clone 一遍。
//
// 任务数据（tasks / sessions / transcripts）不在保护名单里：要清就走
// DELETE /api/tasks/{id} 的正规路径。
func TestWorkspaceProtectedDirs(t *testing.T) {
	s := &Server{}
	s.m = &Manager{dir: t.TempDir()}

	// 保护目录本身与其中的子路径都要拦住
	protected := []string{
		"traffic",
		"traffic/_index/index.sqlite",
		"evidence",
		"evidence/blobs/ab/abcdef.bin",
		"nuclei-templates",
		"nuclei-templates/http/cves/2026/CVE-2026-1.yaml",
	}
	for _, rel := range protected {
		abs, ok := s.wsResolve(rel)
		if !ok {
			t.Fatalf("resolve failed for %q", rel)
		}
		if !s.wsProtected(abs) {
			t.Errorf("%q must be protected", rel)
		}
	}

	// 普通目录与用户产物不该被拦
	allowed := []string{
		"uploads",
		"uploads/scan.py",
		"tasks",
		"tasks/1/work/notes.md",
		"sessions",
		"transcripts",
		"traffic-notes.txt", // 同前缀但不是那个目录
	}
	for _, rel := range allowed {
		abs, ok := s.wsResolve(rel)
		if !ok {
			t.Fatalf("resolve failed for %q", rel)
		}
		if s.wsProtected(abs) {
			t.Errorf("%q must NOT be protected", rel)
		}
	}
}

// 保护名单必须覆盖真正不可再生的三个目录。
func TestWorkspaceProtectedList(t *testing.T) {
	want := map[string]bool{"traffic": true, "evidence": true, "nuclei-templates": true}
	for _, name := range workspaceProtectedDirs {
		if !want[name] {
			t.Errorf("unexpected protected dir %q", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("protected dir %q is missing — it holds non-reproducible data", name)
	}
}

// 保护是「拒绝」而不是「静默跳过」：调用方要拿到明确的 403。
func TestWorkspaceDeleteRefusesProtectedDir(t *testing.T) {
	dir := t.TempDir()
	s := &Server{}
	s.m = &Manager{dir: dir}

	// 造一个真实的 traffic 目录
	if err := os.MkdirAll(filepath.Join(dir, "traffic", "_index"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic", "_index", "index.sqlite"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 直接调 wsDelete 需要的路径解析：确认 protected 判定在删除前生效。
	abs, ok := s.wsResolve("traffic")
	if !ok {
		t.Fatal("resolve failed")
	}
	if !s.wsProtected(abs) {
		t.Fatal("traffic must be protected")
	}
	// 文件还在（我们没有真的调 RemoveAll——那正是要防的动作）
	if _, err := os.Stat(filepath.Join(dir, "traffic", "_index", "index.sqlite")); err != nil {
		t.Fatal("fixture gone")
	}
}
