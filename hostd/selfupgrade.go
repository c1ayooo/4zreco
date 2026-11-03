package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/4zreco/selfupdate"
)

// ValidVersionTag 报告 tag 是否是允许的版本号形态。校验实现放在 selfupdate，
// 与「按版本号取 Release」的逻辑待在一起，避免两处规则漂移。
func ValidVersionTag(tag string) bool { return selfupdate.ValidVersionTag(tag) }

// UpgradeSelf 把助手自己换装到指定 Release 版本。
//
// 为什么必须由助手自己做：它装在 root 拥有的 /usr/local/bin，而主服务受
// ProtectSystem=strict 限制写不进去。
//
// 为什么是「自己下载」而不是「接收主服务递来的文件」：主服务只以运行业务用户的
// 权限跑，一旦它被攻破，让助手安装它指定的任意二进制就等于把 root 执行权交出去。
// 这里坚持自己从官方 Release 拉包、自己按 SHA256SUMS 校验、自己冒烟测试，
// 主服务能影响的只有「装哪个已发布版本」，影响不到「装什么内容」。
func (s *Server) UpgradeSelf(ctx context.Context, tag, proxy string) error {
	tag = strings.TrimSpace(tag)
	if !ValidVersionTag(tag) {
		return fmt.Errorf("版本号格式非法: %q", tag)
	}
	if s.SelfPath == "" {
		return fmt.Errorf("未知自身路径，无法换装")
	}
	dir := filepath.Dir(s.SelfPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("准备目标目录 %s: %w", dir, err)
	}

	c := selfupdate.NewClient(proxy)
	rel, err := selfupdate.FetchByTag(ctx, c, tag)
	if err != nil {
		return err
	}
	// zip 与临时二进制都落在目标目录：跨文件系统 rename 会失败，
	// 而 /tmp 常常是独立挂载点。
	zipPath, err := selfupdate.FetchVerifiedZip(ctx, c, rel, dir, nil)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(zipPath) }()

	tmp := filepath.Join(dir, ".4zreco-hostd.new")
	defer func() { _ = os.Remove(tmp) }()
	if err := selfupdate.ExtractMember(zipPath, "4zreco-hostd", tmp); err != nil {
		return fmt.Errorf("发布包里没有 4zreco-hostd：%w", err)
	}
	if err := selfupdate.SmokeTestBinary(tmp, "-version"); err != nil {
		return fmt.Errorf("新版本无法在当前系统运行：%w", err)
	}
	if err := selfupdate.ReplaceBinary(tmp, s.SelfPath); err != nil {
		return err
	}
	return nil
}
