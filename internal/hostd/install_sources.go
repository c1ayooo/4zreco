package hostd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// InstallSources contains preset IDs. The privileged helper never accepts an
// arbitrary APT or Python package index URL from the web service.
type InstallSources struct {
	APT  string `json:"apt"`
	PyPI string `json:"pypi"`
}

func (s InstallSources) Validate() error {
	if !validSource(s.APT) {
		return fmt.Errorf("未知 APT 镜像")
	}
	if !validSource(s.PyPI) {
		return fmt.Errorf("未知 PyPI 镜像")
	}
	return nil
}

func validSource(id string) bool {
	return id == "" || id == "tencent" || id == "tuna"
}

func pypiIndex(id string) string {
	switch id {
	case "tencent":
		return "https://mirrors.cloud.tencent.com/pypi/simple/"
	case "tuna":
		return "https://pypi.tuna.tsinghua.edu.cn/simple/"
	default:
		return ""
	}
}

// aptSourceArgs copies just the APT source definitions to a temporary directory.
// Passing the same options to update and install leaves the host source files
// and all signature, suite, component and architecture settings intact.
func aptSourceArgs(aptDir, preset string) (args []string, cleanup func(), err error) {
	if preset == "" {
		return nil, func() {}, nil
	}
	host := "mirrors.cloud.tencent.com"
	if preset == "tuna" {
		host = "mirrors.tuna.tsinghua.edu.cn"
	}
	dir, err := os.MkdirTemp("", "4zreco-apt-sources-")
	if err != nil {
		return nil, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	parts := filepath.Join(dir, "sources.list.d")
	if err = os.Mkdir(parts, 0700); err != nil {
		return nil, cleanup, err
	}
	changed := false
	copySource := func(rel string) error {
		data, err := os.ReadFile(filepath.Join(aptDir, rel))
		if err != nil {
			return err
		}
		original := string(data)
		text := rewriteAPTSources(original, filepath.Ext(rel) == ".sources", host)
		changed = changed || text != original
		return os.WriteFile(filepath.Join(dir, rel), []byte(text), 0600)
	}
	if err = copySource("sources.list"); err != nil && !os.IsNotExist(err) {
		return nil, cleanup, err
	}
	entries, err := os.ReadDir(filepath.Join(aptDir, "sources.list.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, cleanup, err
	}
	for _, entry := range entries {
		name := entry.Name()
		ext := filepath.Ext(name)
		if entry.IsDir() || (ext != ".list" && ext != ".sources") {
			continue
		}
		if err = copySource(filepath.Join("sources.list.d", name)); err != nil {
			return nil, cleanup, err
		}
	}
	if !changed {
		return nil, cleanup, fmt.Errorf("未找到可替换的 Debian、Ubuntu 或 Kali 官方 APT 源，请选择系统默认源")
	}
	return []string{
		"-o", "Dir::Etc::sourcelist=" + filepath.Join(dir, "sources.list"),
		"-o", "Dir::Etc::sourceparts=" + parts,
	}, cleanup, nil
}

var (
	aptListURI = regexp.MustCompile(`^[ \t]*deb(?:-src)?[ \t]+(?:\[[^\]\r\n]*\][ \t]+)?(https?://[^\s#]+)`)
	aptURI     = regexp.MustCompile(`\S+`)
)

func rewriteAPTSources(text string, deb822 bool, mirrorHost string) string {
	lines := strings.Split(text, "\n")
	uris := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !deb822 {
			if pos := aptListURI.FindStringSubmatchIndex(line); pos != nil {
				lines[i] = line[:pos[2]] + mirrorAPTURI(line[pos[2]:pos[3]], mirrorHost) + line[pos[3]:]
			}
			continue
		}
		if trimmed == "" {
			uris = false
			continue
		}
		valueStart := 0
		if line[0] != ' ' && line[0] != '\t' {
			field, _, _ := strings.Cut(line, ":")
			uris = strings.EqualFold(field, "URIs") && len(field) < len(line)
			valueStart = len(field) + 1
		}
		if uris {
			lines[i] = line[:valueStart] + aptURI.ReplaceAllStringFunc(line[valueStart:], func(raw string) string {
				return mirrorAPTURI(raw, mirrorHost)
			})
		}
	}
	return strings.Join(lines, "\n")
}

func mirrorAPTURI(raw, mirrorHost string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return raw
	}
	host, repo := strings.ToLower(u.Hostname()), strings.TrimSuffix(u.Path, "/")
	var matched bool
	switch repo {
	case "/ubuntu":
		matched = host == "archive.ubuntu.com" || host == "security.ubuntu.com" || strings.HasSuffix(host, ".archive.ubuntu.com")
	case "/ubuntu-ports":
		matched = host == "ports.ubuntu.com"
	case "/debian":
		matched = host == "deb.debian.org" || host == "ftp.debian.org" || (strings.HasPrefix(host, "ftp.") && strings.HasSuffix(host, ".debian.org"))
	case "/debian-security":
		matched = host == "deb.debian.org" || host == "security.debian.org"
	case "/kali":
		matched = host == "http.kali.org"
	}
	if !matched {
		return raw
	}
	return "https://" + mirrorHost + u.Path
}
