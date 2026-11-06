// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/norma/hook"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/intercept"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	attribSamps map[string][]AttribSample
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
	egress      *EgressGuard           // optional; 出口审查(平台敏感指纹拦截)，nil 关闭
	tarpit      *tarpitState           // optional; tarpit 熔断(每 host 抓取预算)，nil 关闭
	// hitlMode 是 hitl_mode=eino 的 ask 路径开关（P2）：开启时 ask 分支只落库
	// （PersistAsk）并经 ctx 信号交 gate 以 StatefulInterrupt 中断，本进程不再
	// channel 阻塞；关闭（默认，channel 模式）走 HandleAsk 原语义。恢复重入的
	// 验签放行不感知本开关——有恢复数据就核对。
	hitlMode bool
}

// AttribSample 是一条 blocked/error 归因的最近样本（B6）：planner 只看计数时对不上
// 「哪条命令被拦了」，复盘/换打法需要看实物。Command 截断到 attribSampleMax（防御
// 超长命令刷爆态势块），TS 用 Unix 秒便于展示时间。
type AttribSample struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	TS      int64  `json:"ts"`
}

// attribSampleMax 每类保留的样本条数（最近）。计数仍是全量的；样本只是「最近3条」。
const attribSampleMax = 3

// attribSampleMaxBytes 单条 command 的截断长度（字节）。
const attribSampleMaxBytes = 200

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, attribSamps: map[string][]AttribSample{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

// SetHitlMode arms the eino-mode ask path (hitl_mode=settings；默认 channel)。
// 装配点（任务 guard 构建 / chat guard 构建）读开关后调用，运行期不热切——
// 与 checkpoint 装配同一生效时点（4zrec 同款取舍）。
func (g *Guard) SetHitlMode(on bool) {
	g.mu.Lock()
	g.hitlMode = on
	g.mu.Unlock()
}

// hitlOn reads the mode flag under the same mutex as egress (装配期写、运行期读).
func (g *Guard) hitlOn() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hitlMode
}

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// P2-3 恢复重入（先于一切判定）：本调用此前被审批中断、框架带着 checkpoint
	// 重放。核对决定行 + HMAC + 工具名/输入摘要绑定——伪造 resume 不可放行；
	// allowed → 继续原判定管线之外的执行（该调用已审，不再重判/重问）；
	// denied → 管控文本作 tool_result，run 继续（劣化路径同语义）。
	if r := db.HitlResumeFrom(ctx); r != nil {
		return g.applyHitlResume(ctx, ev, r)
	}
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// 出口审查：出站内容含平台敏感指纹（LLM key/jwt.key/PG 密码等）即 deny，
	// 先于一切其他检查——命中时命令原文本身可能带秘密，不能落盘，审计只记 kind。
	if res, stop := g.checkEgress(ev, cmd); stop {
		return res
	}
	g.record(ev.ToolName, "allow", "", cmd)
	// tarpit 熔断：每 host 抓取计数，超预算写一次 hint 提示 planner 停派该方向，
	// 之后对该 host 仍 warn 放行（不硬 block，防误杀真实大站）。
	g.checkTarpit(ev)
	return g.applyIntercept(ctx, ev)
}

// SetEgress 装配出口审查的敏感指纹集合（server 侧进程内共享一份，见
// server/egressguard.go）。nil = 关闭。
func (g *Guard) SetEgress(e *EgressGuard) {
	g.mu.Lock()
	g.egress = e
	g.mu.Unlock()
}

// checkEgress 是 PreToolUse 第一道：对 Bash 类命令全文与 WebFetch 的 url/body
// 做敏感指纹检查，命中 → deny("操作包含平台敏感信息，禁止外发")。
func (g *Guard) checkEgress(ev hook.Event, cmd string) (hook.Result, bool) {
	g.mu.Lock()
	e := g.egress
	g.mu.Unlock()
	if e == nil {
		return hook.Result{}, false
	}
	var texts []string
	if cmd != "" {
		texts = append(texts, cmd)
	}
	if ev.ToolName == "WebFetch" {
		var in struct {
			URL  string `json:"url"`
			Body string `json:"body"`
		}
		if json.Unmarshal(ev.Input, &in) == nil {
			texts = append(texts, in.URL, in.Body)
		}
	}
	for _, text := range texts {
		if text == "" {
			continue
		}
		if kind, hit := e.Check(text); hit {
			// 审计/日志只记 kind：命令原文可能本身就含敏感信息，不落盘；
			// block 文案也不带命中内容，防止把指纹回显给模型。
			log.Printf("[guard][egress] 命中平台敏感指纹(%s),%s 外发已拦截", kind, ev.ToolName)
			return g.block(ev.ToolName, systemBlockMessage("操作包含平台敏感信息，禁止外发"), ""), true
		}
	}
	return hook.Result{}, false
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	} else if dec.Action == "judge" {
		// 规则显式要求「Agent 研判」：不再取固定动作，交给模型裁决；裁决结果仍按
		// allow/deny/ask 走原有分支。保留触发它的 rule_id，审计里能看出是哪条规则
		// 把这次调用交给了模型。
		//
		// 规则自己的 timeout 声明要一起传下去：规则作者显式写了「我超时时怎么办」，
		// 那就以规则为准（否则规则上的 timeout_enabled/seconds/action 仍是死字段，
		// 界面显示的与实际生效的不一致）。规则没写就听全局的。
		ruleID := dec.RuleID
		rt := intercept.RuleTimeout{}
		if dec.TimeoutEnabled {
			rt = intercept.RuleTimeout{
				Enabled: true,
				Seconds: dec.TimeoutSeconds,
				Action:  dec.TimeoutAction,
			}
		}
		d, judged := g.interceptor.JudgeRuleWithTimeout(ctx, ev.ToolName, ev.Input, rt)
		if !judged {
			return hook.Result{}
		}
		d.RuleID = ruleID
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		// P2-2：hitl_mode=eino 时拆两段——落库段照旧（PersistAsk），等待段改为
		// ctx 信号交 gate 以 StatefulInterrupt 中断（checkpoint 落盘，人工决定
		// 后从断点精确续跑）。
		//
		// 先核对信号持有者（评审第 1 轮 #2 的 fail-closed 闸）：gate 半边
		//（SetHitl）与 guard 半边（SetHitlMode）的装配时点可以漂移——灰度期
		// settings 把开关翻回 channel 后，常驻内存的任务 guard 仍 hitlOn，而新
		// 装配的 gate 不再注入持有者。没有这个核对，RaiseAskInterrupt 会在无
		// 持有者时静默丢弃、工具无审批直跑（fail-open）。持有者不存在 → 完整
		// 回退下方的 channel 阻塞语义。
		if g.hitlOn() && db.HasAskSignal(ctx) {
			info, err := g.interceptor.PersistAsk(ctx, convID, dec, ev.ToolName, ev.Input)
			if err != nil {
				log.Printf("[guard] hitl 落库段失败(%v)，按拒绝收口: %s", err, ev.ToolName)
				return g.block(ev.ToolName, systemBlockMessage("审批请求落库失败，按拒绝处理"), "")
			}
			db.RaiseAskInterrupt(ctx, info)
			return hook.Result{}
		}
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// applyHitlResume 是恢复重入的核对与放行（P2-3）：恢复数据必须能与库中决定行
// 对上（签名 + 决定方向 + 工具名 + 输入摘要四重绑定），对不上按拒绝收口——
// 一次校验失败也不能落入「默认放行」。
func (g *Guard) applyHitlResume(ctx context.Context, ev hook.Event, r *db.HitlResumeData) hook.Result {
	if !g.interceptor.VerifyHitlResumeCall(r, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("审批恢复数据校验失败，本次调用不放行"), "")
	}
	if !r.Allowed {
		return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝执行）"), "")
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an 4ZRECO platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【4ZRECO 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	// B6:只留 blocked/error 的实物样本,ok 不占内存。每类环形保留最近 3 条。
	if class != "ok" {
		var input struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &input)
		cmd := input.Command
		if len(cmd) > attribSampleMaxBytes {
			cmd = cmd[:attribSampleMaxBytes]
		}
		samps := append(g.attribSamps[class], AttribSample{Tool: ev.ToolName, Command: cmd, TS: time.Now().Unix()})
		if len(samps) > attribSampleMax {
			samps = samps[len(samps)-attribSampleMax:]
		}
		g.attribSamps[class] = samps
	}
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

// AttributionStats (B6) 是 Attributions 的态势版：计数之外附每类最近样本
// （samples."blocked"/"error" = [{tool,command,ts}...]，最多 3 条，command 截断）。
// planner 看到「blocked×7 + 最近命令列表」就能对上号换打法，而不是只知道「被拦了」。
// 供 graph_overview 的 guard_attributions 块直插使用。
func (g *Guard) AttributionStats() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]any, len(g.attrib)+1)
	for k, v := range g.attrib {
		out[k] = v
	}
	samps := make(map[string]any, len(g.attribSamps))
	for k, v := range g.attribSamps {
		if len(v) > 0 {
			samps[k] = v
		}
	}
	if len(samps) > 0 {
		out["samples"] = samps
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
