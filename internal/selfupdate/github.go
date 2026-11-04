package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Repo 是发布源。
//
// 刻意做成构建期变量而不是**运行时配置项**：更新源可配，等于给任何能改配置的人
// 一条远程代码执行通道，对一个渗透测试平台来说这个口子开不得。二开/镜像要在构建时
// 用 `-ldflags "-X github.com/c1ayooo/4zreco/selfupdate.Repo=owner/name"` 覆盖，
// 这样改的是产物本身，不是运行期可篡改的开关。
var Repo = "c1ayooo/4zreco"

func latestURL() string { return "https://api.github.com/repos/" + Repo + "/releases/latest" }

func tagURL(tag string) string { return "https://api.github.com/repos/" + Repo + "/releases/tags/" + tag }

// allowedHosts 限定升级链路能访问的域名。配合下面的 checkRedirect，
// 任何一跳被重定向到名单外的主机都会直接失败——这是防止 DNS 污染 / 中间人
// 把二进制换掉的第一道闸门，第二道是 SHA256SUMS 比对。
var allowedHosts = map[string]bool{
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true, // release 资产实际落地的对象存储
	"release-assets.githubusercontent.com": true,
	"raw.githubusercontent.com":            true,
}

// Release 是 GitHub Release 里我们关心的字段。
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset 是 Release 上挂的一个文件。
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// NewClient 构造一个只认 GitHub 域名的 HTTP 客户端。proxy 为空则直连。
//
// 刻意不复用默认 Transport：升级链路必须强制走 TLS 且校验证书，不能被别处
// 设置的 InsecureSkipVerify 之类影响到。
func NewClient(proxy string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Minute, // 下载整包，不能按请求级超时卡死
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("重定向次数过多")
			}
			return checkURL(req.URL)
		},
	}
}

// checkURL 强制 https + 域名白名单。
func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("拒绝非 HTTPS 地址: %s", u.Scheme+"://"+u.Host)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("拒绝非 GitHub 域名: %s", u.Hostname())
	}
	return nil
}

// FetchLatest 查询最新正式版。
func FetchLatest(ctx context.Context, c *http.Client) (*Release, error) {
	return fetchRelease(ctx, c, latestURL(), "最新正式版")
}

// FetchByTag 查询指定 tag 的 Release（伴随二进制自我换装时按主程序版本对齐用）。
//
// 版本号有两种写法：Release tag 带 v 前缀（v0.3.23），而二进制里注入的版本号不带
// （build.sh 会 `${ZRECO_BUILD_VERSION#v}` 剥掉）。两种都试，避免因写法差异
// 报"版本不存在"——实测 hostd 拿 0.3.23 去查就撞上了这个。
func FetchByTag(ctx context.Context, c *http.Client, tag string) (*Release, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, fmt.Errorf("缺少版本号")
	}
	rel, err := fetchRelease(ctx, c, tagURL(tag), tag)
	if err == nil {
		return rel, nil
	}
	if rel2, err2 := fetchRelease(ctx, c, tagURL(alternateTag(tag)), tag); err2 == nil {
		return rel2, nil
	}
	return nil, err
}

// alternateTag 返回同一个版本的另一种写法（v0.3.23 ↔ 0.3.23）。
func alternateTag(tag string) string {
	if strings.HasPrefix(tag, "v") {
		return strings.TrimPrefix(tag, "v")
	}
	return "v" + tag
}

func fetchRelease(ctx context.Context, c *http.Client, apiURL, what string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "4zreco-selfupdate")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问 GitHub 失败（可在系统设置里配置全局代理）: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		// 未认证的 GitHub API 是每 IP 每小时 60 次，共用出口 IP 时很容易撞上。
		return nil, fmt.Errorf("GitHub 接口限流（每小时 60 次），请稍后再试")
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("仓库 %s 没有 %s", Repo, what)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub 返回 %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析 Release 失败: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, fmt.Errorf("Release 缺少 tag")
	}
	return &rel, nil
}

// AssetName 返回当前平台对应的发布包名，与 build.sh 的 package_binary 保持一致：
// 4zreco-<版本>-<os>-<arch>.zip（版本号不带 v 前缀）。
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("4zreco-%s-%s-%s.zip", strings.TrimPrefix(tag, "v"), goos, goarch)
}

// FindAsset 在 Release 里按名字找资产。
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}
