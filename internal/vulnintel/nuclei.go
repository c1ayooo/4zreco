package vulnintel

// nuclei-templates 模板树管理与扫描工具支撑:
// - EnsureTemplates:模板树不存在则 git clone --depth 1,存在则 git pull(fast-forward)
// - 模板树落盘在项目目录内部 <Base>/nuclei-templates(与 skills/ 同级,随部署走),
//   不在 <data> 数据目录里——工作空间文件管理器看不到它,也不会误删
// - MigrateTemplates:老部署(模板在 <data>/nuclei-templates)启动时一次性搬过来
// - FindNucleiTemplates(见 poc.go)按 CVE 找模板相对路径
//
// 刻意不引 go-git:git 命令行可用性在运行镜像里有保证(Dockerfile 装 git),
// 且 --depth 1 的浅克隆用命令行最直接。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TemplatesDir 是模板树位置:项目目录内部(Base,可执行文件旁)nuclei-templates/,
// 与 skills/ 同级。调用方传 config.Paths.Base。
func TemplatesDir(baseDir string) string {
	return filepath.Join(baseDir, "nuclei-templates")
}

// MigrateTemplates 把老部署的模板树(<data>/nuclei-templates)一次性搬到新位置
// (<Base>/nuclei-templates)。语义:
//   - 新位置已有效(有 .git 或有模板) → 不动,旧目录留给 6h 循环/人工清理
//   - 旧位置不存在 → 什么都不做(全新部署走 EnsureTemplates 正常 clone)
//   - 旧位置存在 → 先试 os.Rename(同盘瞬时);跨设备(EXDEV,Docker 里 data 是
//     挂载卷而 Base 在容器层)回退递归复制(含 .git,保住后续 git pull 能力),
//     CountTemplates 校验 >0 后删旧目录
//   - 任何失败都不阻断启动:记日志返回错误,下一轮同步循环照常 clone 兜底
func MigrateTemplates(oldDir, newDir string) error {
	if oldDir == newDir {
		return nil
	}
	if _, err := os.Stat(filepath.Join(newDir, ".git")); err == nil {
		return nil // 新位置已是有效模板树
	}
	if CountTemplates(newDir) > 0 {
		return nil // 新位置已有模板(无 .git 的拷贝版也算就绪)
	}
	if _, err := os.Stat(oldDir); err != nil {
		return nil // 无旧目录:全新部署
	}
	if n := CountTemplates(oldDir); n == 0 {
		// 旧位置一个 yaml 都没有 = 损坏残留(半成品 clone,同 v0.3.96 自愈语义):
		// 不迁移,清理掉等同步循环在新位置正常 clone。
		os.RemoveAll(oldDir)
		log.Printf("[vulnintel] 旧模板目录 %s 无 yaml(损坏残留),已清理,等同步循环重新 clone", oldDir)
		return nil
	}
	// 同盘:rename 瞬时完成。
	if err := os.Rename(oldDir, newDir); err == nil {
		log.Printf("[vulnintel] nuclei 模板树已迁移: %s → %s", oldDir, newDir)
		return nil
	}
	// 跨设备/其它失败:递归复制(含 .git),校验后删旧。
	if err := os.MkdirAll(filepath.Dir(newDir), 0o755); err != nil {
		return err
	}
	if err := copyTree(oldDir, newDir); err != nil {
		os.RemoveAll(newDir)
		return fmt.Errorf("nuclei 模板树迁移复制失败(等下轮同步重 clone): %w", err)
	}
	if n := CountTemplates(newDir); n == 0 {
		os.RemoveAll(newDir)
		return errors.New("nuclei 模板树迁移后新位置无 yaml(已清理,等下轮重 clone)")
	}
	if err := os.RemoveAll(oldDir); err != nil {
		log.Printf("[vulnintel] 旧模板目录 %s 删除失败(不影响运行,可手工清理): %v", oldDir, err)
	}
	log.Printf("[vulnintel] nuclei 模板树已迁移(跨盘复制): %s → %s(%d 个模板)", oldDir, newDir, CountTemplates(newDir))
	return nil
}

// copyTree 递归复制目录树(含点开头文件如 .git)。符号链接按其指向内容复制,
// 模板树里没有合法 symlink,遇到即跳过不中断。
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // symlink/设备文件等:模板树不该有,跳过
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	})
}

// EnsureTemplates clones or updates the template tree. Best-effort: returns
// error but callers log it — scan_with_nuclei degrades to "templates
// unavailable" messaging rather than failing the sync.
//
// proxy 是可选出网代理(http/https/socks5，空=直连)。模板树在 github.com，
// 国内/校园网直连必然超时——不传代理时这里只能报 clone failed，所以调用方要用
// 平台配置的「装机代理/全局代理」喂进来，跟拉更新走同一条出口。
//
// 自愈语义（v0.3.96）：clone/pull 失败时清理半成品目录——git 中断残留的 .git
// 空壳会让目录「存在但没有模板」，状态页永远显示 0 个模板且无法自愈（Kali 实测）。
// 成功后校验 yaml 模板数 >0，空树同样按失败清理，下一轮重clone。
func EnsureTemplates(ctx context.Context, dir, proxy string) error {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_HTTP_LOW_SPEED_LIMIT=1000", "GIT_HTTP_LOW_SPEED_TIME=30")
	if proxy != "" {
		// git 认的是 http_proxy/https_proxy（大小写都设一份，不同版本读的不一样），
		// socks5 代理只有 ALL_PROXY 走得通。
		env = append(env,
			"http_proxy="+proxy, "https_proxy="+proxy, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy,
			"ALL_PROXY="+proxy, "all_proxy="+proxy)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// update: fetch + fast-forward only, ignore local drift
		cmd := exec.CommandContext(ctx, "git", "-C", dir, "pull", "--ff-only", "--quiet")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			// 拉取失败分两类：网络/超时（目录留着下次再 pull）；仓库本身损坏
			// （pull 反复失败永远修不好，删掉重 clone 才是自愈）。这里保守处理：
			// 只有目录里一个 yaml 都没有时才视为损坏并清理。
			if CountTemplates(dir) == 0 {
				os.RemoveAll(dir)
				return fmt.Errorf("nuclei templates pull 失败且目录无模板（已清理残留，等下轮重 clone）: %v: %s",
					err, strings.TrimSpace(string(out)))
			}
			return fmt.Errorf("nuclei templates pull: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return verifyTemplates(dir)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--single-branch", "--quiet",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		// clone 失败必留半成品（.git 或部分工作树）——不清理的话下一轮看到 .git
		// 就走 pull 分支，对着残缺仓库 pull，永远修不好（Kali 实测挂了 14 小时）。
		os.RemoveAll(dir)
		return fmt.Errorf("nuclei templates clone（残留已清理，等下轮重试）: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return verifyTemplates(dir)
}

// verifyTemplates 克隆/拉取成功后的内容校验：模板树一个 yaml 都没有 = 无效
// （网络代理返回了错误页、磁盘满等场景产出过空工作树），按失败清理。
func verifyTemplates(dir string) error {
	if n := CountTemplates(dir); n == 0 {
		os.RemoveAll(dir)
		return fmt.Errorf("nuclei templates 校验失败：目录无 yaml 模板（已清理残留，等下轮重试）")
	}
	return nil
}

// CountTemplates 递归统计目录下的 .yaml 模板文件数（.yaml，不含 .yml——
// nuclei-templates 仓库全部用 .yaml）。
func CountTemplates(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 不可读的子树跳过，不中断统计
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".yaml") {
			n++
		}
		return nil
	})
	return n
}

// NucleiInstalled reports whether the nuclei binary is on PATH.
func NucleiInstalled() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// ScanArgs is scan_with_nuclei's validated input.
type ScanArgs struct {
	Target       string        // URL/host to scan
	CVEID        string        // optional: restrict to templates mentioning this CVE
	Severity     string        // optional: comma list critical,high,medium,low
	TimeoutTotal time.Duration // whole-run ceiling (default 10m, cap 30m)
}

// BuildNucleiCmd assembles the nuclei invocation. Templates restricted to the
// local tree (-t <dir>) so we never trigger nuclei's own template download
// (offline-friendly, version-pinned); -silent keeps output parseable; JSONL
// output goes to stdout for the agent to read. The returned cancel MUST be
// called by the caller after the run (it bounds the whole-run ceiling).
func BuildNucleiCmd(ctx context.Context, templatesDir string, a ScanArgs) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(a.Target) == "" {
		return nil, nil, fmt.Errorf("target 不能为空")
	}
	if _, err := os.Stat(filepath.Join(templatesDir, ".git")); err != nil {
		return nil, nil, fmt.Errorf("模板树不可用(%s):先等同步器完成初始化", templatesDir)
	}
	timeout := a.TimeoutTotal
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)

	args := []string{
		"-target", a.Target,
		"-t", templatesDir,
		"-jsonl",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	if cve := strings.TrimSpace(a.CVEID); cve != "" {
		templates := FindNucleiTemplates(templatesDir, cve)
		if len(templates) == 0 {
			cancel()
			return nil, nil, fmt.Errorf("模板树中没有命中 %s 的模板(树可能过期,等下轮同步)", cve)
		}
		for _, rel := range templates {
			args = append(args, "-t", filepath.Join(templatesDir, filepath.FromSlash(rel)))
		}
	}
	if sev := strings.TrimSpace(a.Severity); sev != "" {
		args = append(args, "-severity", sev)
	}
	return exec.CommandContext(runCtx, "nuclei", args...), cancel, nil
}
