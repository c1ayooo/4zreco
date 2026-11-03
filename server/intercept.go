package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreco/db"
	"github.com/c1ayooo/4zreco/guard"
	"github.com/c1ayooo/4zreco/intercept"
	"github.com/c1ayooo/4zreco/llmrec"
	"github.com/Autumn-27/norma/llm"
)

// judgeWorkerLane is the usage-ledger "worker" label for intercept fallback-judge
// calls, so judge spend can be queried apart from the worker/planner/main lanes.
const judgeWorkerLane = "judge"

// chatGuard returns a guard wired with the manager's interceptor, used for chat
// conversations. Called once per applyLLM so a new LLM config always gets a fresh guard.
func (s *Server) chatGuard() *guard.Guard {
	g := guard.NewWithInterceptor(s.m.interceptor)
	if s.m.egress != nil {
		g.SetEgress(s.m.egress) // chat 对话同样过出口敏感指纹拦截
	}
	return g
}

// wireInterceptReviewer installs the LLM fallback judge into the interceptor. The
// judge runs only on tool calls that matched no rule (see intercept.Judge). It
// resolves the configured judge profile (0 → active/default), builds a provider,
// runs a one-shot JSON classification with an explanation for every verdict.
func (s *Server) wireInterceptReviewer() {
	s.m.interceptor.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		if profileID == 0 {
			if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
				profileID = p.ID
			}
		}
		if profileID == 0 {
			return intercept.Decision{}, fmt.Errorf("未配置可用的裁判模型")
		}
		prov, _, ok := s.providerForProfile(profileID)
		if !ok {
			return intercept.Decision{ProfileID: profileID}, fmt.Errorf("裁判模型 profile %d 不可用", profileID)
		}
		// Tag this call's usage as the "judge" lane so the config page can report
		// how much the fallback approval has spent, separate from model profiles.
		ctx = llmrec.WithWorker(ctx, judgeWorkerLane)
		text, err := reviewCompletion(ctx, prov, prompt, input)
		if err != nil {
			return intercept.Decision{ProfileID: profileID}, err
		}
		v := intercept.ParseVerdict(text)
		if v.Action == "" {
			// 把模型原始回复截一段带进错误里：解析失败时只有「格式无效」这四个字
			// 根本没法排查（是缺三段？分隔符不对？还是被 max_tokens 截断了？）。
			//
			// 两种「解析失败」要分开看：
			//   - 回复为空：思考把预算烧光，正文一个字没轮到（长命令常见）。
			//   - 回复被截断成 `{"decision":"al`：JSON 没写完，也是预算不够。
			// 两者都指向同一个解法：给足预算 + 升预算重试。上面
			// streamCollectTextBudget 已经处理了「空回复」的情形；这里再补
			// 「有内容但解析不出来」的升预算重试。
			if retryText, retryErr := reviewCompletionEscalate(ctx, prov, prompt, input, text); retryErr == nil {
				text = retryText
				v = intercept.ParseVerdict(text)
			}
		}
		if v.Action == "" {
			return intercept.Decision{ProfileID: profileID},
				fmt.Errorf("模型裁决格式无效（需要 decision + 三段 comment）：原始回复 %.400q", text)
		}
		return intercept.Decision{Action: v.Action, Message: v.Reason, ProfileID: profileID}, nil
	})
}

// reviewCompletionEscalate 在「有内容但解析不出裁决」时用更高的预算重试一次。
// 典型场景是 JSON 写到一半被 max_tokens 截断（`{"decision":"al`）。
func reviewCompletionEscalate(ctx context.Context, prov llm.Provider, prompt string, input intercept.ReviewInput, first string) (string, error) {
	user, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	for _, b := range judgeRetryBudgets {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		text, err := oneCompletion(ctx, prov, prompt, string(user), b)
		if err != nil {
			return "", err
		}
		if intercept.ParseVerdict(text).Action != "" {
			return text, nil
		}
	}
	return first, nil
}

func reviewCompletion(ctx context.Context, prov llm.Provider, prompt string, input intercept.ReviewInput) (string, error) {
	user, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return streamCollectText(ctx, prov, prompt, string(user))
}

// streamCollectText runs a single non-streaming-style completion (low
// temperature, bounded output) and returns the concatenated text.
//
// thinking 的处理：原先这里硬编码 Thinking:"disabled"，对 MiniMax-M3.1 这类
// **强制要求 adaptive thinking** 的模型会被上游直接拒（400 "requires adaptive
// thinking; thinking.type=disabled is not allowed"）——裁决于是 100% 失败，而失败
// 策略默认 allow，等于这道关卡完全失效。
//
// 现在默认【不发】thinking 字段（空串 = 让模型/网关按自己的默认走），
// 由 profile 的 thinking_type 配置决定；只有显式配了才带上。
//
// max_tokens 必须给足：开启思考的模型会把思考内容算进输出额度，**思考与正文
// 共用同一份预算**。实测长命令（几百到上千字符的 shell 脚本）在 2048 预算下
// 思考烧光、正文为空（裁决记录里表现为「原始回复 ""」）；短命令则 2048 就够。
// 所以这里一次给到 32768，并在正文为空时**逐级升预算重试**——
// 宁可多花点额度，也不能让这道关卡因为预算不够而静默失效。
func streamCollectText(ctx context.Context, prov llm.Provider, system, user string) (string, error) {
	return streamCollectTextBudget(ctx, prov, system, user, judgeMaxTokens)
}

// judgeMaxTokens 是裁决的输出预算（思考+正文共用）。
//
// 32768 的由来：实测同一模型在长命令上 2048 会「思考烧光、正文为空」，
// 短命令 2048 够用。给足预算后长命令也能正常产出三段式 JSON。
const judgeMaxTokens = 32768

// judgeRetryBudgets 是正文为空时的重试预算阶梯。
//
// 为什么要有阶梯：空正文的原因随命令长度而变（输入越长、思考越长），固定预算
// 要么永远不够、要么对短命令过度浪费。逐级升预算既保证长命令能出结果，
// 短命令又不会被无谓地放大额度。
//
// 注意阶梯必须**严格大于**首次预算：首次是 32768，阶梯就从 65536 起，
// 否则第一次重试会用同样的预算再问一遍，纯属浪费一轮往返。
var judgeRetryBudgets = []int{65536, 131072}

// streamCollectTextBudget 在指定预算下取一次回复；正文为空时按阶梯升预算重试。
func streamCollectTextBudget(ctx context.Context, prov llm.Provider, system, user string, budget int) (string, error) {
	var last string
	for i, b := range append([]int{budget}, judgeRetryBudgets...) {
		if i > 0 {
			// 重试前先看 ctx 是否还有预算：裁决有独立超时（默认 90s），
			// 长命令本来就慢，别把时间花在注定超时的重试上。
			if ctx.Err() != nil {
				return last, ctx.Err()
			}
		}
		text, err := oneCompletion(ctx, prov, system, user, b)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(text) != "" {
			return text, nil
		}
		last = text
	}
	return last, nil
}

// oneCompletion 发起一次带预算的完成请求，返回拼接后的文本。
func oneCompletion(ctx context.Context, prov llm.Provider, system, user string, maxTokens int) (string, error) {
	temp := 0.0
	req := llm.CompletionRequest{
		System:      []string{system},
		Messages:    []llm.Message{llm.UserText(user)},
		MaxTokens:   maxTokens,
		Temperature: &temp,
	}
	var sb strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return "", err
		}
		if ev.Type == llm.SETextDelta {
			sb.WriteString(ev.Text)
		}
	}
	return sb.String(), nil
}

// --- intercept rule CRUD ---

func (s *Server) interceptListRules(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rules, err := pg.ListInterceptRules()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rules == nil {
		rules = []db.InterceptRule{}
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}

func (s *Server) interceptCreateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req interceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateInterceptRuleReq(req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.CreateInterceptRule(req.Name, req.MatchTarget, req.MatchType, req.Pattern, req.Action, req.Message, req.Priority, req.Enabled, req.TimeoutEnabled, req.TimeoutSeconds, req.TimeoutAction)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, rule)
}

func (s *Server) interceptUpdateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req interceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateInterceptRuleReq(req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.UpdateInterceptRule(id, req.Name, req.MatchTarget, req.MatchType, req.Pattern, req.Action, req.Message, req.Priority, req.Enabled, req.TimeoutEnabled, req.TimeoutSeconds, req.TimeoutAction)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, rule)
}

func (s *Server) interceptDeleteRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	if err := pg.DeleteInterceptRule(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) interceptToggleRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := pg.ToggleInterceptRule(id, req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": req.Enabled})
}

// --- pending (ask) ---

func (s *Server) interceptListPending(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pending, err := pg.ListPendingIntercepts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if pending == nil {
		pending = []db.InterceptPending{}
	}
	writeJSON(w, 200, map[string]any{"pending": pending})
}

func (s *Server) interceptGetOne(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad pending id")
		return
	}
	p, err := pg.GetInterceptPending(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p == nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) interceptListTaskItems(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID := r.PathValue("taskID")
	if taskID == "" {
		writeErr(w, 400, "bad task id")
		return
	}
	q := r.URL.Query()
	filter, err := interceptFilterParams(q)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if q.Get("page") == "" && q.Get("size") == "" && filter == (db.InterceptApprovalFilter{}) {
		items, err := pg.ListTaskIntercepts(taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if items == nil {
			items = []db.InterceptApprovalRow{}
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	page, size := interceptPageParams(q)
	items, total, err := pg.ListTaskInterceptsPage(taskID, page, size, filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []db.InterceptApprovalRow{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func (s *Server) interceptHistory(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	filter, err := interceptFilterParams(q)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if q.Get("page") == "" && q.Get("size") == "" && filter == (db.InterceptApprovalFilter{}) {
		items, err := pg.ListAllIntercepts(200)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if items == nil {
			items = []db.InterceptApprovalRow{}
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	page, size := interceptPageParams(q)
	items, total, err := pg.ListAllInterceptsPage(page, size, filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []db.InterceptApprovalRow{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func interceptFilterParams(q url.Values) (db.InterceptApprovalFilter, error) {
	filter := db.InterceptApprovalFilter{Status: q.Get("status"), DecisionSource: q.Get("decision_source")}
	switch filter.Status {
	case "", "pending", "allowed", "denied", "timeout":
	default:
		return filter, fmt.Errorf("status 必须是 pending、allowed、denied 或 timeout")
	}
	switch filter.DecisionSource {
	case "", "model", "rule", "unknown":
	default:
		return filter, fmt.Errorf("decision_source 必须是 model、rule 或 unknown")
	}
	return filter, nil
}

func interceptPageParams(q url.Values) (int, int) {
	page := atoiDefault(q.Get("page"), 1)
	size := atoiDefault(q.Get("size"), 20)
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

func (s *Server) interceptDecide(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad pending id")
		return
	}
	var req struct {
		Decision string `json:"decision"` // "allowed" | "denied"
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Decision != "allowed" && req.Decision != "denied" {
		writeErr(w, 400, "decision 必须是 allowed 或 denied")
		return
	}
	if err := s.m.interceptor.Decide(id, req.Decision == "allowed"); err != nil {
		if errors.Is(err, intercept.ErrAlreadyDecided) {
			writeErr(w, 409, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- tool-config (全局工具拦截范围) ---

// interceptGetToolConfig returns the list of tool names that are currently
// configured to enter the intercept rule system.
func (s *Server) interceptGetToolConfig(w http.ResponseWriter, r *http.Request) {
	tools, err := s.m.interceptor.GetEnabledTools()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"enabled_tools": tools})
}

// interceptSetToolConfig replaces the list of tool names that should enter
// the intercept rule system.
func (s *Server) interceptSetToolConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnabledTools []string `json:"enabled_tools"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.EnabledTools == nil {
		req.EnabledTools = []string{}
	}
	if err := s.m.interceptor.SetEnabledTools(req.EnabledTools); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- LLM fallback judge config (全局模型兜底) ---

// interceptGetJudgeConfig returns the resolved judge configuration. Prompt is the
// effective prompt (built-in template when unset), so the UI can prefill it.
func (s *Server) interceptGetJudgeConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.m.interceptor.GetJudgeConfig())
}

// interceptSetJudgeConfig persists the judge configuration.
func (s *Server) interceptSetJudgeConfig(w http.ResponseWriter, r *http.Request) {
	var req intercept.JudgeConfig
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	switch req.FailAction {
	case "allow", "ask", "deny":
	default:
		writeErr(w, 400, "fail_action 必须是 allow、ask 或 deny")
		return
	}
	switch req.AskTimeoutAction {
	case "allow", "deny":
	default:
		writeErr(w, 400, "ask_timeout_action 必须是 allow 或 deny")
		return
	}
	if err := s.m.interceptor.SetJudgeConfig(req); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// interceptJudgeUsage returns the fallback judge's cumulative token spend plus a
// recent daily series, for the config page. ?days bounds the daily series (default 30).
func (s *Server) interceptJudgeUsage(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, db.JudgeUsage{Daily: []db.JudgeDayUsage{}})
		return
	}
	days := atoiDefault(r.URL.Query().Get("days"), 30)
	usage, err := pg.JudgeUsageStats(days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, usage)
}

// --- helpers ---

type interceptRuleReq struct {
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Priority       int    `json:"priority"`
	MatchTarget    string `json:"match_target"`
	MatchType      string `json:"match_type"`
	Pattern        string `json:"pattern"`
	Action         string `json:"action"`
	Message        string `json:"message"`
	TimeoutEnabled bool   `json:"timeout_enabled"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	TimeoutAction  string `json:"timeout_action"`
}

func validateInterceptRuleReq(req interceptRuleReq) error {
	if req.Name == "" {
		return fmt.Errorf("name 不能为空")
	}
	switch req.MatchTarget {
	case "tool_name", "tool_input":
	default:
		return fmt.Errorf("match_target 必须是 tool_name 或 tool_input")
	}
	switch req.MatchType {
	case "string", "regex":
	default:
		return fmt.Errorf("match_type 必须是 string 或 regex")
	}
	if req.Pattern == "" {
		return fmt.Errorf("pattern 不能为空")
	}
	switch req.Action {
	case "allow", "deny", "ask", "judge":
	default:
		return fmt.Errorf("action 必须是 allow、deny、ask 或 judge")
	}
	if req.MatchType == "regex" {
		if _, err := regexp.Compile(req.Pattern); err != nil {
			return fmt.Errorf("pattern 不是有效正则：%w", err)
		}
	}
	// timeout_action 必须落在允许集合内。
	//
	// 这个字段现在**真的生效**（2026-10-22 起，规则自己的 timeout 声明优先
	// 于全局 judge 配置），所以它不再只是一个存进库里的字符串：写进任意值
	// 会让「超时后到底放行还是拒绝」变成未定义行为——判定时
	// `dec.TimeoutAction == "allow"` 会把任何非 "allow" 的值当成拒绝，
	// 而界面显示的却是那个乱写的字符串。
	switch req.TimeoutAction {
	case "allow", "deny":
	default:
		return fmt.Errorf("timeout_action 必须是 allow 或 deny")
	}
	if req.TimeoutEnabled && req.TimeoutSeconds <= 0 {
		return fmt.Errorf("启用超时时 timeout_seconds 必须为正数")
	}
	return nil
}

func (s *Server) interceptDetail(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad approval id")
		return
	}
	detail, err := pg.GetInterceptDetail(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if detail == nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, detail)
}

// The navigation endpoint returns only the original call and its paired result.
func (s *Server) interceptExecution(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad approval id")
		return
	}
	target, err := pg.GetInterceptExecution(id)
	if errors.Is(err, db.ErrInterceptTaskDeleted) || errors.Is(err, db.ErrInterceptSessionDeleted) {
		writeErr(w, http.StatusGone, err.Error())
		return
	}
	if errors.Is(err, db.ErrInterceptExecutionUnavailable) {
		writeErr(w, 409, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if target == nil {
		// Conversation deletion cascades approval rows. A stale source link still
		// carries its conversation ID, allowing a precise message without retaining
		// deleted conversations or changing their deletion semantics.
		if convID, parseErr := strconv.ParseInt(r.URL.Query().Get("conversation"), 10, 64); parseErr == nil && convID > 0 {
			conv, getErr := pg.GetConversation(convID)
			if getErr != nil {
				writeErr(w, 500, getErr.Error())
				return
			}
			if conv == nil {
				writeErr(w, http.StatusGone, "对话已被删除")
				return
			}
		}
		writeErr(w, 404, "审批记录已被删除或不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"conversation_id": target.ConversationID, "task_id": target.TaskID, "session": target.Session, "seq": target.Seq, "items": activityDTOs(target.Items)})
}
