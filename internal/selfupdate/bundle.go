package selfupdate

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// 本文件提供"下载并校验发布包 / 从包里取出某个文件"两个原子操作。
//
// 拆出来是为了让**伴随二进制**（4zreco-hostd）复用同一套安全校验：它由 root 常驻、
// 装在 /usr/local/bin，主服务写不进去，只能由它自己换装；如果它另写一份下载校验
// 逻辑，两边迟早会出现一处漏校验的情况。
//
// 校验链与主程序完全一致：Release 资产名 → SHA256SUMS 收录的摘要 → 实算摘要比对。

// FetchVerifiedZip 下载 rel 对应当前平台/架构的发布包，按 SHA256SUMS 校验后返回
// 本地路径。调用方负责删除返回的文件。
//
// 文件落在 dir 下而不是 /tmp：/tmp 常常是独立挂载点，跨设备 rename 会失败。
func FetchVerifiedZip(ctx context.Context, c *http.Client, rel *Release, dir string, prog Progress) (string, error) {
	if rel == nil {
		return "", fmt.Errorf("缺少 Release 信息")
	}
	if prog == nil {
		prog = func(Phase, int, string) {}
	}
	name := AssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	asset, ok := rel.FindAsset(name)
	if !ok {
		return "", fmt.Errorf("该版本没有提供 %s/%s 的发布包（缺少 %s）", runtime.GOOS, runtime.GOARCH, name)
	}

	prog(PhaseDownload, 0, "获取校验和清单…")
	sums, err := fetchSums(ctx, c, rel)
	if err != nil {
		return "", err
	}
	want, ok := sums[name]
	if !ok {
		return "", fmt.Errorf("%s 未收录 %s，拒绝安装未经校验的二进制", sumsAsset, name)
	}

	zipPath := filepath.Join(dir, name+".part")
	prog(PhaseDownload, 0, fmt.Sprintf("下载 %s（%s）…", name, humanSize(asset.Size)))
	got, err := download(ctx, c, asset, zipPath, prog)
	if err != nil {
		_ = os.Remove(zipPath)
		return "", err
	}

	prog(PhaseVerify, -1, "校验 SHA256…")
	if !strings.EqualFold(got, want) {
		_ = os.Remove(zipPath)
		return "", fmt.Errorf("SHA256 不匹配：期望 %s，实际 %s（下载损坏或被篡改）", short(want), short(got))
	}
	return zipPath, nil
}

// ExtractMember 从发布包里取出**基名**为 baseName 的文件写到 dst（0755）。
//
// 按基名匹配而不是拼完整路径：包内目录名带版本号，拼错一个字符就整个失败；
// 按基名找更耐改，也不会被包内多余的层级影响。
func ExtractMember(zipPath, baseName, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开发布包: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Base(entry.Name), baseName) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("读取 %s: %w", entry.Name, err)
		}
		defer rc.Close()

		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("写出 %s: %w", baseName, err)
		}
		defer f.Close()

		n, err := io.Copy(f, io.LimitReader(rc, maxBinarySize+1))
		if err != nil {
			return fmt.Errorf("解压 %s: %w", entry.Name, err)
		}
		if n > maxBinarySize {
			return fmt.Errorf("发布包内的 %s 超过 %s，拒绝解压", baseName, humanSize(maxBinarySize))
		}
		if n == 0 {
			return fmt.Errorf("发布包内的 %s 是空文件", baseName)
		}
		return f.Sync()
	}
	return fmt.Errorf("发布包里没有找到 %s", baseName)
}

// ReplaceBinary 原子地把 newPath 装到 target（保留旧版为 target+".prev"）。
//
// 用于伴随二进制自我换装：同目录 rename 是原子的；旧版留一份，装完起不来还能手工退回。
func ReplaceBinary(newPath, target string) error {
	prev := target + ".prev"
	_ = os.Remove(prev)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, prev); err != nil {
			return fmt.Errorf("备份当前版本: %w", err)
		}
	}
	if err := os.Rename(newPath, target); err != nil {
		// 装不上就把旧的放回去，否则下次重启没有可执行文件。
		if rerr := os.Rename(prev, target); rerr != nil {
			return fmt.Errorf("装入新版本失败(%v)，且恢复旧版本失败: %w", err, rerr)
		}
		return fmt.Errorf("装入新版本: %w", err)
	}
	_ = os.Chmod(target, 0o755)
	return nil
}

// SmokeTestBinary 用 -h 拉起一个二进制，确认它在当前系统上真的能执行。
// 挡掉下载截断、架构选错（exec format error）、缺动态库这类问题。
func SmokeTestBinary(bin string, args ...string) error {
	if len(args) == 0 {
		args = []string{"-h"}
	}
	return smokeTestWithArgs(bin, args)
}

// 供 SmokeTestBinary 复用的超时常量。
const smokeTimeout = 30 * time.Second

// smokeTestWithArgs 是冒烟测试的实现，允许调用方指定探测参数
// （4zreco 用 -h；4zreco-hostd 用 -version，因为它 -h 也会 exit 0 但输出更短）。
func smokeTestWithArgs(bin string, args []string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("赋予执行权限: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("冒烟测试超时（新二进制无响应）")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("冒烟测试失败: %v: %s", err, snippet)
	}
	return nil
}
