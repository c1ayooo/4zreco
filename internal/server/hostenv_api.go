// 宿主环境 API:体检 + 一键安装。
//
// 「一键安装」的实现在特权助手 4zreco-hostd 里(见 hostd 包)——主服务受
// NoNewPrivileges + ProtectSystem=strict 限制无法提权,只能经 Unix socket 把
// 请求转过去。本文件是这层转发 + 前端契约。
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/internal/hosttools"
	"github.com/c1ayooo/4zreco/internal/proxyprobe"
	"github.com/c1ayooo/4zreco/internal/selfupdate"
)

// 默认 socket 路径,与 hostd 单元里的 -socket 一致;可用环境变量覆盖。
const defaultHostdSocket = "/run/4zreco/hostd.sock"

func hostdSocket() string {
	if p := strings.TrimSpace(os.Getenv("ZRECO_HOSTD_SOCKET")); p != "" {
		return p
	}
	return defaultHostdSocket
}

// hostdClient 只经 Unix socket 访问助手:没有任何 TCP 面。
func hostdClient() *http.Client {
	sock := hostdSocket()
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

// hostdProbe 探测助手是否在线,返回 (在线, 原因)。原因用于前端解释为什么不能装。
func (s *Server) hostdProbe(ctx context.Context) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://hostd/healthz", nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := hostdClient().Do(req)
	if err != nil {
		return false, "宿主助手未运行（未安装 4zreco-hostd，或当前是 Docker 部署）"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "宿主助手响应异常: HTTP " + resp.Status
	}
	return true, ""
}

// installProxy 读「安装期出网代理」设置。与运行期的目标代理/LLM 代理无关:
// 它只作用于 apt/curl/GitHub 下载。
//
// 环境变量 ZRECO_INSTALL_PROXY 是兜底：Docker 形态没有 config.json，
// install.sh 只能通过 compose 传进来。数据库 setting 优先（可被页面改写），
// 环境变量只在没配 setting 时生效。
func (s *Server) installProxy() string {
	if s.m != nil && s.m.pg != nil {
		v, _, _ := s.m.pg.GetSetting(settingInstallProxy)
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return strings.TrimSpace(os.Getenv("ZRECO_INSTALL_PROXY"))
}

// maintenanceProxy 维护类出网（检查/下载更新、安装宿主工具）走哪个代理。
//
// 优先「装机代理」——它本来就是为「连 GitHub 拉东西」准备的；老部署没配过它时
// 回落到全局代理，保证行为不变。两者语义不同：全局代理是给**目标流量**隐藏源 IP
// 用的，拿它去拉更新只是历史上没有别的选择。
func (s *Server) maintenanceProxy() string {
	if p := s.installProxy(); p != "" {
		return p
	}
	if s.m == nil {
		return ""
	}
	return s.m.GlobalProxy()
}

// hostenvStatus 体检页的总入口:工具清单 + 是否支持一键安装。
func (s *Server) hostenvStatus(w http.ResponseWriter, r *http.Request) {
	ver, present := s.hostdVersion(r.Context())
	reason := ""
	if !present {
		reason = "宿主助手未运行（未安装 4zreco-hostd，或当前是 Docker 部署）"
	}
	writeJSON(w, 200, map[string]any{
		"tools": hosttools.Inventory(),
		"deploy_mode": deployMode(),
		"installer": map[string]any{
			"available": present,
			"reason":    reason,
			"version":   ver,
			// 老助手（0.3.22 之前）既不上报版本也没有 /self-upgrade，自己换不了装，
			// 需要运维重跑一次 install.sh 引导；之后就能自动跟随主程序升级。
			"upgrade_required": present && ver == "",
			"socket":           hostdSocket(),
			"proxy":            s.installProxy(), // 回显当前安装代理,前端可编辑
		},
	})
}

// hostenvInstall 请求安装一个工具,转发给助手。
func (s *Server) hostenvInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeErr(w, 400, "缺少工具 id")
		return
	}
	// 白名单在主服务侧先挡一道(助手侧还会再挡),避免无谓的跨进程调用。
	if _, ok := hosttools.Lookup(req.ID); !ok {
		writeErr(w, 400, "未知工具: "+req.ID)
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"tool_id": req.ID,
		"proxy":   s.installProxy(),
	})
	body, code, err := s.hostdCall(r.Context(), http.MethodPost, "/jobs", payload)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// hostenvInstallBatch 批量发起安装——「一键装齐」的后端。
//
// 助手侧的任务模型天然支持排队（执行信号量容量 1，后续任务进 queued 串行等待），
// 所以这里只是把 N 个单工具安装**顺序转发**过去：不新增助手侧协议、不引入并发
// 安装（apt 并发跑会锁冲突）。某个工具发起失败（已安装/不支持一键/助手忙拒绝）
// 不影响其余工具——结果里逐项带回成功/跳过，前端据此展示。
func (s *Server) hostenvInstallBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "缺少工具 id 列表")
		return
	}
	if len(req.IDs) > 100 {
		writeErr(w, 400, "一次最多 100 个工具")
		return
	}
	proxy := s.installProxy()
	type jobOK struct {
		JobID  string `json:"job_id"`
		ToolID string `json:"tool_id"`
	}
	type skip struct {
		ToolID string `json:"tool_id"`
		Reason string `json:"reason"`
	}
	var started []jobOK
	var skipped []skip
	seen := map[string]bool{}
	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue // 空项与重复项静默跳过
		}
		seen[id] = true
		if _, ok := hosttools.Lookup(id); !ok {
			skipped = append(skipped, skip{ToolID: id, Reason: "未知工具"})
			continue
		}
		payload, _ := json.Marshal(map[string]string{"tool_id": id, "proxy": proxy})
		body, code, err := s.hostdCall(r.Context(), http.MethodPost, "/jobs", payload)
		if err != nil {
			// 助手整体不可用：没必要继续打剩下的一定也失败。
			writeErr(w, 503, err.Error())
			return
		}
		if code/100 != 2 {
			// 助手明确拒绝（已安装/KindManual/代理非法）——记原因继续下一个。
			skipped = append(skipped, skip{ToolID: id, Reason: strings.TrimSpace(string(body))})
			continue
		}
		var j struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &j) != nil || j.ID == "" {
			skipped = append(skipped, skip{ToolID: id, Reason: "助手响应缺少任务 id"})
			continue
		}
		started = append(started, jobOK{JobID: j.ID, ToolID: id})
	}
	writeJSON(w, 200, map[string]any{
		"started": started,
		"skipped": skipped,
	})
}

// hostenvProxyCheck 测试一个代理是否真的可用。
//
// 用户要的是「代理随时能改」——代理会失效，所以改完必须能立刻验证，
// 而不是装工具时才发现连不上。不传 proxy 时测当前生效的代理。
//
// 判定口径与 install.sh 装机期一致（都走 proxyprobe 包）：两边说"通"，
// 就真的是同一条链路。
func (s *Server) hostenvProxyCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy string `json:"proxy"`
		// UseCurrent = true 时测当前生效的代理（忽略 body 里的 proxy）。
		UseCurrent bool `json:"use_current"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	raw := strings.TrimSpace(req.Proxy)
	if req.UseCurrent || raw == "" {
		raw = s.installProxy()
	}
	raw = proxyprobe.Normalize(raw)

	clean, err := proxyprobe.Validate(raw)
	if err != nil {
		writeJSON(w, 400, map[string]any{
			"ok":    false,
			"proxy": raw,
			"error": err.Error(),
			"hint":  "格式应为 http://host:port、https://host:port、socks5://host:port 或 socks5h://host:port（可带 user:pass@）",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res := proxyprobe.Probe(ctx, clean, "", "https://api.ipify.org?format=json")

	// 200 带 ok:false 是「测了，不通」——不是接口错误，前端要能区分。
	writeJSON(w, 200, res)
}

// hostenvJob 查询安装任务进度(前端轮询)。
func (s *Server) hostenvJob(w http.ResponseWriter, r *http.Request) {
	body, code, err := s.hostdCall(r.Context(), http.MethodGet, "/jobs/"+r.PathValue("id"), nil)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// hostenvCancel 取消安装任务。
func (s *Server) hostenvCancel(w http.ResponseWriter, r *http.Request) {
	body, code, err := s.hostdCall(r.Context(), http.MethodPost, "/jobs/"+r.PathValue("id")+"/cancel", nil)
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// hostdCall 把一个请求转给助手,原样带回状态码与响应体。
func (s *Server) hostdCall(ctx context.Context, method, path string, payload []byte) ([]byte, int, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://hostd"+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hostdClient().Do(req)
	if err != nil {
		return nil, 0, errConnectHostd(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

type hostdUnavailable struct{ msg string }

func (e hostdUnavailable) Error() string { return e.msg }

func errConnectHostd(err error) error {
	return hostdUnavailable{"宿主助手不可用（未安装 4zreco-hostd，或当前是 Docker 部署）: " + err.Error()}
}

// hostdVersion 查询助手版本。
//
// present=false 表示助手不在（Docker 部署 / 未安装 / 未启动）。
// version="" 且 present=true 表示助手能应答但不具备版本上报能力——`/version` 是
// 0.3.22 才加的，所以这种助手必然早于 0.3.22，也就**没有 /self-upgrade**，
// 无法自我换装，只能由运维重跑一次 install.sh 引导上来。
func (s *Server) hostdVersion(ctx context.Context) (version string, present bool) {
	if body, code, err := s.hostdCall(ctx, http.MethodGet, "/version", nil); err == nil && code == http.StatusOK {
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(body, &v) == nil && strings.TrimSpace(v.Version) != "" {
			return strings.TrimSpace(v.Version), true
		}
	}
	// 回退 /healthz：老版本有它、没有 /version。能应答就说明助手在。
	if _, code, err := s.hostdCall(ctx, http.MethodGet, "/healthz", nil); err == nil && code == http.StatusOK {
		return "", true
	}
	return "", false
}

// StartHostdReconcile 在后台把助手版本对齐到主程序版本。
//
// 为什么需要它：助手 4zreco-hostd 装在 root 拥有的 /usr/local/bin，主服务受
// ProtectSystem=strict 限制写不进去，所以**助手的升级只能由助手自己完成**。
// 主程序每次自我升级后重启，这里发现版本落后就通知助手自我换装；助手会自己从
// 官方 Release 下载并按 SHA256SUMS 校验，主程序能影响的只有"装哪个已发布版本"。
func (s *Server) StartHostdReconcile() {
	go func() {
		// 等主服务与助手都稳定下来，别和启动抢资源。
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		for attempt := 1; attempt <= 5; attempt++ {
			if s.reconcileHostdOnce() {
				return
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
		log.Printf("[hostd] 版本对齐放弃重试（助手始终不可达）")
	}()
}

// reconcileHostdOnce 做一次版本对齐。返回 true 表示无需再重试。
func (s *Server) reconcileHostdOnce() bool {
	want := strings.TrimSpace(BuildVersion)
	// dev / git describe 构建（带后缀）不参与对齐，避免开发版覆盖正式助手。
	if _, ok := selfupdate.CompareVersions(want, want); !ok {
		return true
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	got, present := s.hostdVersion(ctx)
	if !present {
		return false // 助手还没起来，稍后重试
	}
	if got == want {
		return true
	}
	if got == "" {
		// 老助手既不上报版本，也没有 /self-upgrade —— 它自己换不了装。
		// 这是一次性的引导窗口：重跑一次 install.sh 换上带自换装能力的新助手后，
		// 之后每次发版就都能自动跟随了。
		log.Printf("[hostd] 助手版本过旧（不支持版本上报与自换装），需重跑一次 install.sh 完成引导")
		return true
	}
	log.Printf("[hostd] 版本不一致（助手 %s / 主程序 %s），请求助手自我换装", got, want)

	payload, _ := json.Marshal(map[string]string{
		"tag":   want,
		"proxy": s.maintenanceProxy(),
	})
	body, code, err := s.hostdCall(ctx, http.MethodPost, "/self-upgrade", payload)
	if err != nil {
		log.Printf("[hostd] 请求自我换装失败：%v", err)
		return false
	}
	if code/100 != 2 {
		log.Printf("[hostd] 请求自我换装被拒（HTTP %d）：%s", code, strings.TrimSpace(string(body)))
		return true // 被拒（版本号非法 / 已在升级中）重试无益
	}
	log.Printf("[hostd] 已请求换装到 %s，助手会自行重启", want)
	return true
}
