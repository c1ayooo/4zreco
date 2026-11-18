package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// 预置凭据登录熔断（U1，上游 v0.4.82 issue #24；本地口径见方案 G3「折中」决策）。
//
// ## 为什么需要它
//
// 任务预置的测试凭据密码过期/被目标管理员改密后，不同意图的多个 worker 会各自
// 调 session_login 反复尝试——目标系统的连续失败锁定策略会把客户的测试账号甚至
// 生产账号锁死。这是授权/合规层面的事故：锁号之后不仅任务做不下去，客户关系也
// 受损。模型侧提示词拦不住这种风暴（每个 worker 只看到自己那一次 401），
// 所以必须在 Go 执行层做确定性熔断。
//
// ## 语义（账号级共享计数 + 任务级一次性豁免）
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
//   - **计数按账号维度共享**：状态键只由 asset_id + auth_index 构成（不含任务），
//     同一客户账号被多个任务同时使用时失败次数累加——不会出现「N 个任务各打
//     2 次」这种把目标账号锁死的形态。
//   - **任务级一次性豁免**：熔断期内某个任务确需确认账号是否已被管理员解锁，
//     可在 session_login 传 breaker_probe=true 显式申请一次放行；每个任务对同一
//     凭据只有一次机会（用过即记入 ProbedBy）。放行后仍 401/403 会立即重新熔断
//     （失败计数不回退），成功则整条状态（含豁免记录）删除。
//   - 凭据内容变化（操作员在资产上改密/换 token）自动复位：状态按凭据哈希
//     归属，哈希不同视为新凭据。
//   - 传输错误（连接失败/代理故障）不计失败——那是出口问题，不是凭据问题。
//
// ## 为什么不做持久化
//
// 熔断状态在内存：进程重启清零，重新开始计数。预置凭据连续失败风暴的窗口是
// 任务运行期，重启窗口足够小；持久化反而要解决「重启后误伤新任务」的复杂度。
// 豁免集合 ProbedBy 的量级是「同账号并发任务数」，成功/改密即随状态回收，
// 不需要定时清理线程。
const (
	loginBreakerThreshold = 2
	loginBreakerLockTTL   = 30 * time.Minute
)

// loginBreakerState 是一条预置凭据（账号维度）的熔断状态。
type loginBreakerState struct {
	SecretHash  string    // 当前凭据内容的哈希：变了 = 操作员改了凭据，自动复位
	Failures    int       // 连续鉴权失败次数（成功清零）
	LockedUntil time.Time // 非零 = 熔断中，到点后放行一次（half-open）
	LastStatus  int       // 最近一次失败的 HTTP 状态码
	UpdatedAt   time.Time
	ProbedBy    map[int64]bool // 已用掉一次性试探的任务 ID；成功或复位时整条删除
}

var (
	loginBreakerMu     sync.Mutex
	loginBreakerStates = map[string]*loginBreakerState{}
	loginBreakerNow    = time.Now // 测试注入用
)

// loginBreakerKey 返回一条预置凭据的熔断状态键与其内容哈希。键按【账号】维度
// （asset_id + auth_index，不含任务）——同一客户账号跨任务共享失败计数，这是
// 防锁号的核心；任务维度只体现在一次性豁免的 ProbedBy 里。
func loginBreakerKey(assetID int64, authIndex int, username, secret string) (key, secretHash string) {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s|%s", assetID, authIndex, username, secret)))
	return fmt.Sprintf("asset/%d/%d", assetID, authIndex), hex.EncodeToString(h[:12])
}

// loginBreakerCheck 在发起登录请求前调用。返回 (locked, message)：
//   - locked=true：调用方必须本地拒绝，不得发出任何网络请求；message 为拒绝原因。
//   - locked=false 且 message 非空：本次使用了任务级一次性试探放行，调用方应把
//     message 附在结果里告知模型（每任务每凭据仅一次）。
func loginBreakerCheck(key, secretHash string, taskID int64, probe bool) (locked bool, message string) {
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
			if probe && taskID > 0 && !st.ProbedBy[taskID] {
				if st.ProbedBy == nil {
					st.ProbedBy = map[int64]bool{}
				}
				st.ProbedBy[taskID] = true
				return false, fmt.Sprintf(
					"已使用本任务对该预置凭据的一次性试探放行（每个任务仅一次）：本次登录会真实发往目标。该凭据此前已连续 %d 次鉴权失败（最近一次 HTTP %d）；若本次仍失败将立即重新熔断，请勿反复重试。",
					st.Failures, st.LastStatus)
			}
			remain := st.LockedUntil.Sub(now).Round(time.Second)
			hint := ""
			if probe && taskID > 0 {
				hint = "（本任务的一次性试探已用完）"
			} else if taskID > 0 {
				hint = "（确需确认账号是否已被管理员解锁，可传 breaker_probe=true 使用本任务的一次性试探）"
			}
			return true, fmt.Sprintf(
				"该预置凭据已连续 %d 次鉴权失败（最近一次 HTTP %d），已熔断约 %s：本地直接拒绝，不再向目标发起登录请求，避免触发目标账号锁定策略锁死客户账号。请改测未授权面，或通知操作员在资产上更新/重置该凭据（更新后自动恢复）。%s",
				st.Failures, st.LastStatus, remain, hint)
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
	st.Failures++
	st.LastStatus = status
	st.UpdatedAt = now
	if st.Failures >= loginBreakerThreshold {
		st.LockedUntil = now.Add(loginBreakerLockTTL)
		return fmt.Sprintf(
			"⚠️ 该预置凭据已连续 %d 次鉴权失败（HTTP %d），已熔断 %s：后续 session_login 引用此凭据将被本地拒绝、不再发请求（所有任务共享该熔断，避免多任务并发把客户账号锁死）。请换资产上的其他凭据（auth_index）、改测未授权面，或通知操作员更新/重置该凭据。",
			st.Failures, status, loginBreakerLockTTL)
	}
	return fmt.Sprintf("该预置凭据已连续 %d 次鉴权失败（HTTP %d）；再失败 %d 次将熔断并不再向目标发起登录（熔断按账号跨任务共享）。请优先换 auth_index 或改测未授权面。",
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
