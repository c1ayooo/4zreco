package server

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// 批量 Word 导出（移植自上游 v0.4.48）：stage 下的 .docx 打包 zip，
// 非 docx 成员跳过、子目录跳过。
func TestZipDocxFiles(t *testing.T) {
	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "4zreco-finding-1.docx"), []byte("PK-fake-1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "4zreco-finding-2.docx"), []byte("PK-fake-2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stage, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "out.zip")
	if err := zipDocxFiles(stage, zipPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if len(names) != 2 || !names["4zreco-finding-1.docx"] || !names["4zreco-finding-2.docx"] {
		t.Fatalf("zip members=%v want exactly the two .docx", names)
	}
}
