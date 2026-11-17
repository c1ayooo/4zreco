package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// 工作区里的符号链接不能成为读/写/删的逃生通道（上游 0.4.80 #17）。
//
// wsResolve 原本只做 Clean+HasPrefix 的词法判断：工作区内的 link -> /etc
// 词法上仍是 data/link，读/写都会顺着链接落进根目录之外。修法是第二道校验
// ——已存在的目标按 EvalSymlinks 解析真实路径，尚不存在的目标解析最近存在
// 的父目录后再接受。
func TestWorkspaceResolveRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &Server{}
	s.m = &Manager{dir: base}
	for _, rel := range []string{"link/secret", "link/new-file"} {
		if _, ok := s.wsResolve(rel); ok {
			t.Fatalf("workspace escape via %q was accepted", rel)
		}
	}
	if abs, ok := s.wsResolve("safe/new-file"); !ok || !pathWithin(base, abs) {
		t.Fatalf("safe path rejected: abs=%q ok=%v", abs, ok)
	}
	if abs, ok := s.wsResolve(""); !ok || filepath.Clean(abs) != filepath.Clean(base) {
		t.Fatalf("workspace root rejected: abs=%q ok=%v", abs, ok)
	}
}

// 工作区内指向受保护目录的符号链接不能成为写入口。
//
// wsProtected 原本只按词法前缀判断：alias -> traffic 的词法路径 data/alias
// 不带 traffic 前缀，write/mkdir/upload 都能顺着链接写进 traffic。修法是
// wsProtected 按解析后的真实路径判定（目标不存在时解析最近存在的父目录），
// upload 还要对每个最终落点再核一次（同名文件本身可能就是符号链接）。
func TestWorkspaceSymlinkCannotWriteProtectedDirs(t *testing.T) {
	data := t.TempDir()
	traffic := filepath.Join(data, "traffic")
	if err := os.MkdirAll(traffic, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(traffic, "existing.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(data, "alias")
	if err := os.Symlink(traffic, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &Server{}
	s.m = &Manager{dir: data}

	// write：alias/pwned.txt 实际落在 traffic/
	body, _ := json.Marshal(map[string]string{"path": "alias/pwned.txt", "content": "pwned"})
	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", bytes.NewReader(body)))
	if w.Code != 403 {
		t.Fatalf("write through symlink: status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "pwned.txt")); err == nil {
		t.Fatal("write through symlink created a file in protected traffic dir")
	}

	// mkdir：alias/new-dir 实际落在 traffic/
	body, _ = json.Marshal(map[string]string{"path": "alias/new-dir"})
	w = httptest.NewRecorder()
	s.wsMkdir(w, httptest.NewRequest("POST", "/api/workspace/mkdir", bytes.NewReader(body)))
	if w.Code != 403 {
		t.Fatalf("mkdir through symlink: status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "new-dir")); err == nil {
		t.Fatal("mkdir through symlink created a directory in protected traffic dir")
	}

	// upload 到 alias/ 目录：目录本身是符号链接
	upload := func(dir string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "upload.txt")
		_, _ = fw.Write([]byte("pwned"))
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/api/workspace/upload?path="+dir, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		s.wsUpload(rec, req)
		return rec
	}
	if rec := upload("alias"); rec.Code != 403 {
		t.Fatalf("upload into symlinked dir: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "upload.txt")); err == nil {
		t.Fatal("upload into symlinked dir created a file in protected traffic dir")
	}

	// 最终目标本身是符号链接：uploads/upload.txt -> traffic/existing.txt
	uploads := filepath.Join(data, "uploads")
	if err := os.MkdirAll(uploads, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(traffic, "existing.txt"), filepath.Join(uploads, "upload.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if rec := upload("uploads"); rec.Code != 403 {
		t.Fatalf("upload onto symlinked file: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
	if got, err := os.ReadFile(filepath.Join(traffic, "existing.txt")); err != nil || string(got) != "keep" {
		t.Fatalf("upload overwrote protected file through symlink: got=%q err=%v", got, err)
	}

	// delete：alias 词法上不是 traffic，但真实路径就是保护目录本身
	w = httptest.NewRecorder()
	s.wsDelete(w, httptest.NewRequest("DELETE", "/api/workspace/delete?path=alias", nil))
	if w.Code != 403 {
		t.Fatalf("delete through symlink: status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(traffic, "existing.txt")); err != nil {
		t.Fatal("delete through symlink removed protected traffic dir")
	}

	// 正常路径仍可写（不能因为修复把所有写入都挡掉）
	body, _ = json.Marshal(map[string]string{"path": "notes/a.txt", "content": "ok"})
	w = httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("normal write rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}
