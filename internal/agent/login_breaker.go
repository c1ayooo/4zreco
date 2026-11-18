package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// 预置凭据登录熔断（U1，上游 v0.4.82 issue #24）。
//
// ## 为什么需要它
//
// 任务预置的测试凭据密码过期/被目标管理员改密后，不同意图的多个 worker 会各自
// 调 session_login 反复尝试——目标系统的连续失败锁定策略会把客户的测试账号甚至
// 生产账号锁死。这是授权/合规层面的事故：锁号之后不仅任务做不下去，客户关系也
// 受损。模型侧提示词拦不住这种风暴（每个 worker 只看到自己那一次 401），
// 所以必须在 Go 执行层做确定性熔断。
//
// ## 语义
//
//   - 只管【预置凭据】（资产上登记、经 asset_id+auth_index 引用的）：显式传
//     username/password 的是模型一次性手输，没有「同一凭据被反复打」的形态，
//     不纳入熔断。
//   - 判失败只认 401/403（明确的鉴权拒绝）；2xx 视为成功清零计数；其余状态码
//     （5xx、4xx 其他、3xx）是中性结果——既不算失败也不清零，避免目标偶发故障
//     或模型参数写错把计数刷爆。
//   - 连续 loginBreakerThreshold 次 401/403 → 熔断 loginBreakerLockTTL：
//     期间 session_login 对该凭据【本地直接拒绝，不发任何网络请求】。
//     TTL 到期放行一次（half-open）：成功则复位，仍 401/403 则重新熔断——
//     覆盖「目标侧被锁账号后来被管理员解锁」的场景，凭据没变也能恢复。
//   - 凭据内容变化（操作员在资产上改密/换 token）自动复位：状态按凭据哈希
//     归属，哈希不同视为新凭据。
//   - 传输错误（连接失败/代理故障）不计失败——那是出口问题，不是凭据问题。
//
// ## 为什么不做持久化
//
// 熔断状态在内存：进程重启清零，重新开始计数。预置凭据连续失败风暴的窗口是
// 任务运行期，重启窗口足够小；持久化反而要解决「重启后误伤新任务」的复杂度。
const (
	loginBreakerThreshold = 2
	loginBreakerLockTTL   = 30 * time.Minute
)

// loginBreakerState 是一条预置凭据的熔断状态。
type loginBreakerState struct {
	SecretHash  string    // 当前凭据内容的哈希：变了 = 操作员改了凭据，自动复位
	Failures    int       // 连续鉴权失败次数（成功清零）
	LockedUntil time.Time // 非零 = 熔断中，到点后放行一次（half-open）
	LastStatus  int       // 最近一次失败的 HTTP 状态码
	UpdatedAt   time.Time
}

var (
	loginBreakerMu     sync.Mutex
	loginBreakerStates = map[string]*loginBreakerState{}
	loginBreakerNow    = time.Now // 测试注入用
)

// loginBreakerKey 返回一条预置凭据的熔断状态键与其内容哈希。键按任务隔离
// （不同任务对同一资产的尝试互不影响），哈希含凭据内容——改密即换身份。
func loginBreakerKey(taskID, assetID, authIndex int64, username, secret string) (key, secretHash string) {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%d|%s|%s", taskID, assetID, authIndex, username, secret)))
	return fmt.Sprintf("%d/%d/%d", taskID, assetID, authIndex), hex.EncodeToString(h[:12])
}

// loginBreakerCheck 在发起登录请求前调用。返回 (locked, message)：
// locked=true 时调用方必须本地拒绝，不得发出任何网络请求。
func loginBreakerCheck(key, secretHash string) (bool, string) {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	st, ok := loginBreakerStates[key]
	if !ok {
		return false, ""
	}
	if st.SecretHash != secretHash {
		// 凭据被操作员更新过：旧熔断状态作废，视为新凭据。
		delete(loginBreakerStates, key)
		return false, ""
	}
	now := loginBreakerNow()
	if !st.LockedUntil.IsZero() {
		if now.Before(st.LockedUntil) {
			remain := st.LockedUntil.Sub(now).Round(time.Second)
			return true, fmt.Sprintf(
				"该预置凭据已连续 %d 次鉴权失败（最近一次 HTTP %d），已熔断约 %s：本地直接拒绝，不再向目标发起登录请求，避免触发目标账号锁定策略锁死客户账号。请改测未授权面，或通知操作员在资产上更新/重置该凭据（更新后自动恢复）。",
				st.Failures, st.LastStatus, remain)
		}
		// TTL 已过：half-open 放行一次。保留累计状态，若这次仍失败会立即重新熔断。
		st.LockedUntil = time.Time{}
	}
	return false, ""
}

// loginBreakerRecordFailure 记一次鉴权失败。返回非空 message 表示达到阈值、
// 已进入熔断，调用方应把它附在工具返回里告知模型。
func loginBreakerRecordFailure(key, secretHash string, status int) string {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	now := loginBreakerNow()
	st, ok := loginBreakerStates[key]
	if !ok || st.SecretHash != secretHash {
		st = &loginBreakerState{SecretHash: secretHash}
		loginBreakerStates[key] = st
	}
	// half-open 放行后再次失败：保持累计计数（已 >= 阈值），直接重新熔断。
	st.Failures++
	st.LastStatus = status
	st.UpdatedAt = now
	if st.Failures >= loginBreakerThreshold {
		st.LockedUntil = now.Add(loginBreakerLockTTL)
		return fmt.Sprintf(
			"⚠️ 该预置凭据已连续 %d 次鉴权失败（HTTP %d），已熔断 %s：后续 session_login 引用此凭据将被本地拒绝、不再发请求，避免触发目标账号锁定策略锁死客户账号。请换资产上的其他凭据（auth_index）、改测未授权面，或通知操作员更新/重置该凭据。",
			st.Failures, status, loginBreakerLockTTL)
	}
	return fmt.Sprintf("该预置凭据已连续 %d 次鉴权失败（HTTP %d）；再失败 %d 次将熔断并不再向目标发起登录。请优先换 auth_index 或改测未授权面。",
		st.Failures, status, loginBreakerThreshold-st.Failures)
}

// loginBreakerRecordSuccess 记一次登录成功：清零计数、解除熔断。
func loginBreakerRecordSuccess(key, secretHash string) {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	st, ok := loginBreakerStates[key]
	if !ok || st.SecretHash != secretHash {
		return
	}
	delete(loginBreakerStates, key)
}

// resetLoginBreakers 清空全部熔断状态（仅测试使用）。
func resetLoginBreakers() {
	loginBreakerMu.Lock()
	defer loginBreakerMu.Unlock()
	loginBreakerStates = map[string]*loginBreakerState{}
}

// classifyLoginOutcome 把一次登录响应归为 success / failure / neutral。
// 401/403 是明确的鉴权拒绝；2xx 视为成功；其余（5xx、4xx 其他、3xx）中性。
func classifyLoginOutcome(status int) string {
	switch {
	case status == 401 || status == 403:
		return "failure"
	case status >= 200 && status < 300:
		return "success"
	}
	return "neutral"
}
