package hostd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPTSourceArgsPreservesHostSources(t *testing.T) {
	aptDir := t.TempDir()
	parts := filepath.Join(aptDir, "sources.list.d")
	if err := os.Mkdir(parts, 0700); err != nil {
		t.Fatal(err)
	}
	originalList := "# deb http://http.kali.org/kali kali-rolling main\n" +
		"deb [arch=arm64 signed-by=/keys/ubuntu.gpg] http://ports.ubuntu.com/ubuntu-ports/ noble main\n" +
		"deb https://packages.example.org/debian stable main\n"
	original822 := `Types: deb deb-src
URIs: https://deb.debian.org/debian
 https://security.debian.org/debian-security
Suites: trixie
Components: main non-free-firmware
Signed-By: /keys/debian.gpg

Types: deb
URIs: https://deb.debian.org.evil.example/debian
Suites: trixie
Signed-By: /keys/custom.gpg
`
	originals := map[string]string{
		"sources.list":                  originalList,
		"sources.list.d/debian.sources": original822,
	}
	for name, content := range originals {
		if err := os.WriteFile(filepath.Join(aptDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args, cleanup, err := aptSourceArgs(aptDir, "tuna")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	listPath := strings.TrimPrefix(args[1], "Dir::Etc::sourcelist=")
	partsPath := strings.TrimPrefix(args[3], "Dir::Etc::sourceparts=")
	assertFile := func(path, want string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s: got %q (%v), want %q", path, got, err, want)
		}
	}
	assertFile(listPath, strings.Replace(originalList, "http://ports.ubuntu.com", "https://mirrors.tuna.tsinghua.edu.cn", 1))
	want822 := strings.Replace(original822, "https://deb.debian.org/debian", "https://mirrors.tuna.tsinghua.edu.cn/debian", 1)
	want822 = strings.Replace(want822, "https://security.debian.org/debian-security", "https://mirrors.tuna.tsinghua.edu.cn/debian-security", 1)
	assertFile(filepath.Join(partsPath, "debian.sources"), want822)
	for name, content := range originals {
		assertFile(filepath.Join(aptDir, name), content)
	}
	cleanup()
	if _, err := os.Stat(listPath); !os.IsNotExist(err) {
		t.Fatalf("temporary sources still exist: %v", err)
	}
}

func TestAPTSourceArgsWithAPT(t *testing.T) {
	apt, err := exec.LookPath("apt-get")
	if err != nil {
		t.Skip("apt-get not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sources.list"), []byte("deb [signed-by=/keys/debian.gpg] https://deb.debian.org/debian stable main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args, cleanup, err := aptSourceArgs(dir, "tencent")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// --print-uris reads the selected sources without downloading or installing anything.
	args = append(args, "-o", "Dir::State::lists="+t.TempDir(), "-o", "Debug::NoLocking=true", "--print-uris", "update")
	out, err := exec.Command(apt, args...).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "https://mirrors.cloud.tencent.com/debian/dists/stable/InRelease") {
		t.Fatalf("APT did not select the mirror: %v\n%s", err, out)
	}
}

func TestAPTSourceArgsNoOfficialSource(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sources.list"), []byte("deb https://example.org/debian stable main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := aptSourceArgs(dir, "tencent"); err == nil {
		t.Fatal("a preset without a matching source should report an error")
	}
}

func TestInstallSourceJobRejectsCustomIndex(t *testing.T) {
	handler := NewServer(nil, nil).Handler()
	w := httptest.NewRecorder()
	body := `{"tool_id":"not-a-tool","sources":{"pypi":"https://example.org/simple/"}}`
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/jobs/with-sources", strings.NewReader(body)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "未知 PyPI 镜像") {
		t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
	}
}
