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

// MigrateTemplates 把老部署 <data>/nuclei-templates 一次性搬到 <Base>/nuclei-templates。
// 同盘走 rename；跨盘走复制+校验+删旧（EXDEV 无法在测试里稳定复现，复制路径以
// 「rename 失败即走复制」的结构保证可达）。失败不阻断启动是硬约束。
func TestMigrateTemplates(t *testing.T) {
	makeTree := func(t *testing.T, dir string) {
		t.Helper()
		y := filepath.Join(dir, "http", "cves")
		if err := os.MkdirAll(y, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(y, "a.yaml"), []byte("id: x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: x\n"), 0o644); err != nil {
			t.Fatal(err) // 用占位文件代表 .git，保住「rename 保留 git 元数据」的语义
		}
	}

	t.Run("全新部署无旧目录-不做事", func(t *testing.T) {
		base, data := t.TempDir(), t.TempDir()
		if err := MigrateTemplates(filepath.Join(data, "nuclei-templates"), TemplatesDir(base)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(TemplatesDir(base)); !os.IsNotExist(err) {
			t.Fatal("新位置不应被创建")
		}
	})

	t.Run("同盘迁移-rename 且旧目录消失", func(t *testing.T) {
		base, data := t.TempDir(), t.TempDir()
		makeTree(t, filepath.Join(data, "nuclei-templates"))
		if err := MigrateTemplates(filepath.Join(data, "nuclei-templates"), TemplatesDir(base)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(data, "nuclei-templates")); !os.IsNotExist(err) {
			t.Fatal("旧目录应已消失")
		}
		if CountTemplates(TemplatesDir(base)) != 1 {
			t.Fatal("新位置应有 1 个模板")
		}
		if _, err := os.Stat(filepath.Join(TemplatesDir(base), ".git")); err != nil {
			t.Fatal(".git 应随 rename 保留（后续 git pull 依赖它）")
		}
	})

	t.Run("新位置已就绪-旧目录不动", func(t *testing.T) {
		base, data := t.TempDir(), t.TempDir()
		makeTree(t, TemplatesDir(base))
		makeTree(t, filepath.Join(data, "nuclei-templates"))
		if err := MigrateTemplates(filepath.Join(data, "nuclei-templates"), TemplatesDir(base)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(data, "nuclei-templates")); err != nil {
			t.Fatal("旧目录不应被动（留给人工/后续清理，避免误删数据）")
		}
	})

	t.Run("旧目录无模板-视为损坏不迁移", func(t *testing.T) {
		base, data := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(filepath.Join(data, "nuclei-templates"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := MigrateTemplates(filepath.Join(data, "nuclei-templates"), TemplatesDir(base)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(TemplatesDir(base)); !os.IsNotExist(err) {
			t.Fatal("空模板树不应迁移（等同步循环正常 clone）")
		}
	})
}
