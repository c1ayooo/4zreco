// Package docpreview 把任务里抓到的 Office / PDF 文档取样渲染成图片：
// Office（doc/xls/ppt/csv）先经 LibreOffice 转 PDF，再用 poppler 的 pdftoppm
// 渲染前 N 页为 JPEG。只做无状态的转换，落库/排队由调用方负责。
package docpreview

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrSofficeMissing / ErrPdftoppmMissing 让调用方能区分“依赖没装”和“文档坏了”。
var (
	ErrSofficeMissing  = errors.New("未安装 LibreOffice（soffice）")
	ErrPdftoppmMissing = errors.New("未安装 poppler-utils（pdftoppm）")
)

// DefaultPages 是每份文档的取样页数上限。
const DefaultPages = 3

// 单次转换的时间上限：LibreOffice 冷启动 + 大文档可能慢，但不能无限挂。
const convertTimeout = 120 * time.Second

// KindFor 按扩展名判断文档类型；返回空串表示不支持预览。
// Kubernetes 无关；命名与 server 的 artifact kind 对齐：document/spreadsheet/
// presentation/pdf。
func KindFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".doc", ".docx", ".odt", ".rtf":
		return "document"
	case ".xls", ".xlsx", ".ods", ".csv":
		return "spreadsheet"
	case ".ppt", ".pptx", ".odp":
		return "presentation"
	case ".pdf":
		return "pdf"
	}
	return ""
}

// Supports 报告该文件是否可生成预览。
func Supports(name string) bool { return KindFor(name) != "" }

// Generate 把 src 渲染到 outDir/page-1.jpg...，最多 maxPages 页，返回实际页数。
// outDir 会被创建（已存在则覆盖同名页文件）；临时文件自动清理。
func Generate(ctx context.Context, src, outDir string, maxPages int) (int, error) {
	if maxPages <= 0 {
		maxPages = DefaultPages
	}
	if st, err := os.Stat(src); err != nil || !st.Mode().IsRegular() {
		return 0, fmt.Errorf("源文件不可读")
	}
	if !Supports(src) {
		return 0, fmt.Errorf("不支持的文件类型：%s", filepath.Ext(src))
	}
	tmp, err := os.MkdirTemp("", "4zreco-preview-")
	if err != nil {
		return 0, fmt.Errorf("创建临时目录：%w", err)
	}
	defer os.RemoveAll(tmp)

	pdf := src
	if KindFor(src) != "pdf" {
		pdf, err = officeToPDF(ctx, src, tmp)
		if err != nil {
			return 0, err
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, fmt.Errorf("创建预览目录：%w", err)
	}
	// 清掉上一次的页文件，避免重试后残留多余页。
	if olds, _ := filepath.Glob(filepath.Join(outDir, "page-*.jpg")); len(olds) > 0 {
		for _, f := range olds {
			_ = os.Remove(f)
		}
	}
	return pdfToJPEGs(ctx, pdf, outDir, maxPages)
}

// officeToPDF 用 LibreOffice headless 转 PDF。隔离 UserInstallation，避免并发
// 抢同一个用户 profile；HOME 也指向临时目录，防止往服务用户家目录写文件。
func officeToPDF(ctx context.Context, src, tmp string) (string, error) {
	bin, err := findSoffice()
	if err != nil {
		return "", err
	}
	profile := filepath.ToSlash(filepath.Join(tmp, "lo-profile"))
	profileURL := "file://" + profile
	if !strings.HasPrefix(profile, "/") {
		profileURL = "file:///" + profile // Windows: file:///C:/...
	}
	runCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()
	args := []string{
		"--headless", "--norestore", "--nologo", "--nolockcheck", "--nodefault",
		"-env:UserInstallation=" + profileURL,
		"--convert-to", "pdf", "--outdir", tmp, src,
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+tmp)
	// cwd 必须是可访问目录：soffice 包装脚本会 cd 回启动时目录（比如以 root
	// 从 /root 启动、再 sudo -u 4zreco 运行时，4zreco 无权进入 /root 直接失败）。
	cmd.Dir = tmp
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("LibreOffice 转换超时（%s）", convertTimeout)
		}
		if msg != "" {
			return "", fmt.Errorf("LibreOffice 转换失败：%v（%s）", runErr, msg)
		}
		return "", fmt.Errorf("LibreOffice 转换失败：%v", runErr)
	}
	matches, _ := filepath.Glob(filepath.Join(tmp, "*.pdf"))
	if len(matches) == 0 {
		return "", fmt.Errorf("LibreOffice 未产出 PDF")
	}
	// 优先同名 PDF，否则取第一个（LibreOffice 可能规整文件名）。
	want := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src)) + ".pdf"
	for _, m := range matches {
		if strings.EqualFold(filepath.Base(m), want) {
			return m, nil
		}
	}
	return matches[0], nil
}

// pdfToJPEGs 渲染前 maxPages 页。输出页文件名归一为 page-1.jpg...，避免
// pdftoppm 按总页数补零（page-01.jpg）导致前端拼 URL 不稳定。
//
// pdftoppm 先写 outDir 内的临时子目录再 rename：/tmp 与数据盘常不在同一
// 文件系统，跨设备 rename 会 EXDEV 失败（Kali 实测）。
func pdfToJPEGs(ctx context.Context, pdf, outDir string, maxPages int) (int, error) {
	bin, err := findPdftoppm()
	if err != nil {
		return 0, err
	}
	stage, err := os.MkdirTemp(outDir, ".stage-")
	if err != nil {
		return 0, fmt.Errorf("创建预览暂存目录：%w", err)
	}
	defer os.RemoveAll(stage)
	prefix := filepath.Join(stage, "page")
	runCtx, cancel := context.WithTimeout(ctx, convertTimeout)
	defer cancel()
	args := []string{
		"-jpeg", "-jpegopt", "quality=82", "-r", "110", "-scale-to", "1600",
		"-f", "1", "-l", strconv.Itoa(maxPages), pdf, prefix,
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Dir = stage
	out, runErr := cmd.CombinedOutput()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return 0, fmt.Errorf("PDF 渲染超时（%s）", convertTimeout)
	}
	if runErr != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		if msg != "" {
			return 0, fmt.Errorf("PDF 渲染失败：%v（%s）", runErr, msg)
		}
		return 0, fmt.Errorf("PDF 渲染失败：%v", runErr)
	}
	files, _ := filepath.Glob(prefix + "-*.jpg")
	if len(files) == 0 {
		return 0, fmt.Errorf("PDF 未产出页面图片（文件可能加密或损坏）")
	}
	sort.Slice(files, func(i, j int) bool {
		return pageNo(files[i]) < pageNo(files[j])
	})
	if len(files) > maxPages {
		files = files[:maxPages]
	}
	for i, f := range files {
		dst := filepath.Join(outDir, fmt.Sprintf("page-%d.jpg", i+1))
		if err := os.Rename(f, dst); err != nil {
			return 0, fmt.Errorf("写入预览页：%w", err)
		}
		_ = os.Chmod(dst, 0o644) // maint 以 root 跑时也要让服务用户可读
	}
	return len(files), nil
}

func pageNo(path string) int {
	base := strings.TrimSuffix(filepath.Base(path), ".jpg")
	i := strings.LastIndex(base, "-")
	if i < 0 {
		return 0
	}
	n, _ := strconv.Atoi(base[i+1:])
	return n
}

func findSoffice() (string, error) {
	if p, err := lookFirst([]string{"soffice", "libreoffice"},
		`C:\Program Files\LibreOffice\program\soffice.exe`,
		`C:\Program Files (x86)\LibreOffice\program\soffice.exe`,
		"/Applications/LibreOffice.app/Contents/MacOS/soffice",
	); err == nil {
		return p, nil
	}
	return "", ErrSofficeMissing
}

func findPdftoppm() (string, error) {
	if p, err := lookFirst([]string{"pdftoppm"},
		`C:\Program Files\poppler\Library\bin\pdftoppm.exe`,
		`C:\Program Files\poppler\bin\pdftoppm.exe`,
		"/opt/homebrew/bin/pdftoppm",
	); err == nil {
		return p, nil
	}
	return "", ErrPdftoppmMissing
}

// lookFirst 先查 PATH，再查常见安装路径（Windows/macOS 的 GUI 安装器通常
// 不改 PATH）。
func lookFirst(names []string, candidates ...string) (string, error) {
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("not found")
}

// Available 报告两个依赖是否齐全（宿主环境页/排障用）。
func Available() (soffice, pdftoppm bool) {
	_, err1 := findSoffice()
	_, err2 := findPdftoppm()
	return err1 == nil, err2 == nil
}
