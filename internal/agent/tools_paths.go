package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 工具级文件入参的公共限界：把「模型给一个路径」收敛成「任务目录内的普通文件」。
// 与 parse_poc_template 的模板树限界同一范式（pocTemplateRelPath）：
//   - 两侧 EvalSymlinks 后做 Rel 判定——词法前缀挡不住目录内符号链接指向目录外；
//   - 扩展名白名单 + 大小上限，避免误传大文件/非目标文件把 worker 卡住。
//
// 之所以单独成文件：J3（滑块图）与 J7（nuclei JSONL）都要这套校验，复制两份迟早
// 会分叉（一处忘了 EvalSymlinks 就是任意文件读取面）。

// workspaceRelPath 校验 target 在 root 内，返回相对路径与解析后的真实绝对路径。
// 目标不存在时解析父目录再拼回，让调用方拿到「不可读」而不是含糊的「越界」。
func workspaceRelPath(root, target string) (rel, abs string, err error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", "", fmt.Errorf("工作目录非法: %v", err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("路径非法: %v", err)
	}
	realRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", "", fmt.Errorf("工作目录不可用: %v", err)
	}
	realTarget, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		parent, perr := filepath.EvalSymlinks(filepath.Dir(targetAbs))
		if perr != nil {
			return "", "", fmt.Errorf("路径不可用: %v", err)
		}
		realTarget = filepath.Join(parent, filepath.Base(targetAbs))
	}
	rel, err = filepath.Rel(realRoot, realTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("路径越界：不在本意图工作目录内")
	}
	return rel, realTarget, nil
}

// readWorkspaceFile 读任务目录内、扩展名白名单内、不超过 maxBytes 的普通文件。
func readWorkspaceFile(runDir, path string, exts map[string]bool, maxBytes int64) ([]byte, string, error) {
	r := strings.TrimSpace(runDir)
	if r == "" {
		return nil, "", errors.New("当前运行没有工作目录，只能直接给内容")
	}
	target := strings.TrimSpace(path)
	if target == "" {
		return nil, "", errors.New("路径不能为空")
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(r, target)
	}
	rel, abs, err := workspaceRelPath(r, target)
	if err != nil {
		return nil, "", err
	}
	if len(exts) > 0 {
		ext := strings.ToLower(filepath.Ext(rel))
		if !exts[ext] {
			allowed := make([]string, 0, len(exts))
			for e := range exts {
				allowed = append(allowed, e)
			}
			return nil, "", fmt.Errorf("扩展名 %q 不在允许范围 %v 内", ext, allowed)
		}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, "", fmt.Errorf("文件不可读: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("不是普通文件: %s", rel)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, "", fmt.Errorf("文件 %d 字节超过上限 %d", info.Size(), maxBytes)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, "", fmt.Errorf("读取失败: %v", err)
	}
	return data, rel, nil
}
