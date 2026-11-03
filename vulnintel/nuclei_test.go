package vulnintel

import (
	"os"
	"path/filepath"
	"testing"
)

// CountTemplates 是模板树自愈的判定基准：clone/pull 失败后「目录里一个 yaml
// 都没有」= 损坏残留，清理重 clone；有模板 = 只网络抖动，保留目录下次 pull。
func TestCountTemplates(t *testing.T) {
	dir := t.TempDir()
	if n := CountTemplates(dir); n != 0 {
		t.Fatalf("empty dir: got %d, want 0", n)
	}
	// 造一个 nuclei-templates 形状的树：子目录 + .yaml，外加一个不该数的 .yml/.txt
	y := filepath.Join(dir, "http", "cves", "2026")
	if err := os.MkdirAll(y, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(y, "a.yaml"), []byte("id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(y, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.yaml"), []byte("id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nope.yml"), []byte("id: y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := CountTemplates(dir); n != 2 {
		t.Fatalf("got %d, want 2（.yml 与非 yaml 不计）", n)
	}
}
