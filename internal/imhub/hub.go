package imhub

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	pgdb "github.com/c1ayooo/4zreco/internal/db"
)

// hub.go IM 接入网关：把飞书/钉钉/Telegram/企业微信里发来的消息接进平台的
// 对话链路。每个 IM chat(platform+chat_id) 固定映射一个平台会话（im_sessions 表）：
// 斜杠命令 /bond /new /commands 直接复用对话页那套处理（commands.go），自然
// 语言经 TurnRunner（宿主注入，与 web 对话页共用 busy 控制与运行链路）跑同一个
// agent 轮，web 与 IM 看到同一条会话记录。
//
// 回程按平台适配器发送（feishu.go / dingtalk.go / telegram.go / wecom.go）。
// 配置存 settings（config.go），变化即全停重起各平台循环。
//
// 分层约定：本包只做协议/路由/命令/会话映射，依赖 internal/db 与 internal/notify；
// 对话驱动链（busy 表 + runConversationSync）是宿主（internal/server）的状态，
// 经 TurnRunner 接口注入——不在本包复制一份调度语义。

// WecomCallbackPath 是企业微信回调端点路径（宿主注册路由 + requireAuth 豁免 +
// 回显 callback_url 三处共用一个常量，防漂移）。
const WecomCallbackPath = "/api/im/wecom/callback"

// TurnRunner 由宿主实现：跑一轮 agent 对话并同步等最终回复。busy 控制与 user
// 活动落库由宿主实现（busy key "conv-<id>" 与 web 对话页共用同一张表，IM 与
// web 在同一会话上互相排队）。
type TurnRunner interface {
	RunTurn(conv *pgdb.Conversation, text string) string
}

// Hub 管理各平台收发循环与入站派发。pg/runner 必填；BaseURL/AckNote 可选。
type Hub struct {
	pg     *pgdb.DB
	runner TurnRunner

	// BaseURL 返回平台外部可达地址（企微回调 URL 回显用，同 notify 回链配置）。
	BaseURL func() string
	// AckNote 返回「处理中」回执文案；返回空串用默认文案。宿主可在 HITL eino
	// 模式下附加「去 web 审批」提示——该模式下 agent 轮可能 park 等审批，
	// IM 侧同步等待期间只有这条回执。
	AckNote func() string

	ctx     context.Context
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// New 构造网关。pg 为 nil 时 Start 是空操作（无 DB 不接 IM）。
func New(ctx context.Context, pg *pgdb.DB, runner TurnRunner) *Hub {
	return &Hub{ctx: ctx, pg: pg, runner: runner}
}

// Start 初始化并按当前配置启动已启用平台的循环（宿主装配时调用一次；
// 之后凭据/开关变化走 Apply → ApplyConfig 热更）。
func (h *Hub) Start() {
	if h.pg == nil {
		return
	}
	h.mu.Lock()
	if h.cancels == nil {
		h.cancels = map[string]context.CancelFunc{}
	}
	h.mu.Unlock()
	h.ApplyConfig()
}

// ApplyConfig 按当前配置对齐各平台循环：停掉已关闭/多余的，补启新开启的。
// 企业微信没有常驻循环（入站走 HTTP 回调、出站按需发送），不在这里管理。
func (h *Hub) ApplyConfig() {
	cfg := h.LoadConfig()
	want := map[string]bool{}
	if cfg.Feishu.Enabled && cfg.Feishu.AppID != "" && cfg.Feishu.AppSecret != "" {
		want["feishu"] = true
	}
	if cfg.Dingtalk.Enabled && cfg.Dingtalk.ClientID != "" && cfg.Dingtalk.ClientSecret != "" {
		want["dingtalk"] = true
	}
	if cfg.Telegram.Enabled && cfg.Telegram.BotToken != "" {
		want["telegram"] = true
	}

	type imSpawn struct {
		platform string
		ctx      context.Context
	}
	var spawns []imSpawn
	h.mu.Lock()
	if h.cancels == nil {
		// 未走 Start（如测试或极早的 Apply）也能安全对齐循环。
		h.cancels = map[string]context.CancelFunc{}
	}
	for platform, cancel := range h.cancels {
		if !want[platform] {
			cancel()
			delete(h.cancels, platform)
		}
	}
	for platform := range want {
		if _, running := h.cancels[platform]; running {
			continue
		}
		ctx, cancel := context.WithCancel(h.ctx)
		h.cancels[platform] = cancel
		spawns = append(spawns, imSpawn{platform: platform, ctx: ctx})
	}
	h.mu.Unlock()

	for _, sp := range spawns {
		switch sp.platform {
		case "feishu":
			go h.imFeishuLoop(sp.ctx, cfg)
		case "dingtalk":
			go h.imDingtalkLoop(sp.ctx, cfg)
		case "telegram":
			go h.imTelegramLoop(sp.ctx, cfg)
		}
		log.Printf("[im] %s 接入已启动", sp.platform)
	}
}

// HandleText 是所有平台入站文本的统一入口。text 已由适配器归一化（去 @ 提及、
// 去空白）；msgID 是平台侧的原消息 id（用于盖「处理中」表情，可为空）。
// 命令即时回执；agent 轮先盖表情（或回文本）再回结果。
func (h *Hub) HandleText(platform, chatID, userID, msgID, text string) {
	if h.pg == nil {
		return
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	pg := h.pg
	cfg := h.LoadConfig()

	conv := h.sessionConversation(platform, chatID, userID, cfg)
	if conv == nil {
		return // 开会话失败已回执
	}

	if cmd, ok := ParseChatCommand(text); ok {
		reply := h.handleCommand(pg, platform, chatID, userID, conv, cmd)
		if reply != "" {
			h.Reply(platform, chatID, reply)
		}
		return
	}

	// 处理中信号：支持表情的平台在原消息上盖 Typing、回复后移除；否则回一条文本。
	ack := "收到，正在处理…"
	if h.AckNote != nil {
		if note := h.AckNote(); note != "" {
			ack = note
		}
	}
	reactionID := h.imAckWorking(platform, msgID)
	if reactionID == "" {
		h.Reply(platform, chatID, ack)
	}
	if reply := h.agentTurn(conv, text); reply != "" {
		h.Reply(platform, chatID, reply)
	}
	if reactionID != "" {
		h.imClearWorking(platform, msgID, reactionID)
	}
}

// imAckWorking 给原消息盖「处理中」表情（仅飞书实现）；返回 reaction_id 供回复后
// 移除，空串表示平台不支持或盖失败（调用方退回文本回执）。
func (h *Hub) imAckWorking(platform, msgID string) string {
	if msgID == "" || h.pg == nil {
		return ""
	}
	cfg := h.LoadConfig()
	switch platform {
	case "feishu":
		rid, err := h.imFeishuReact(context.Background(), cfg, msgID, imFeishuWorkingEmoji)
		if err != nil {
			log.Printf("[im feishu] 盖处理中表情失败: %v", err)
			return ""
		}
		return rid
	}
	return ""
}

// imClearWorking 回复送达后移除「处理中」表情（失败只记日志，不影响结果）。
func (h *Hub) imClearWorking(platform, msgID, reactionID string) {
	if msgID == "" || reactionID == "" {
		return
	}
	cfg := h.LoadConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch platform {
	case "feishu":
		if err := h.imFeishuUnreact(ctx, cfg, msgID, reactionID); err != nil {
			log.Printf("[im feishu] 移除处理中表情失败: %v", err)
		}
	}
}

// sessionConversation 返回该 chat 映射的会话；没有或已删则按配置开新会话。
// IM 开的会话不挂项目/任务（project_id/task_id 保持 NULL）——归属绑定经 /bond
// 显式设置，IM 来源标注进标题，web 对话页一眼可辨。
func (h *Hub) sessionConversation(platform, chatID, userID string, cfg Config) *pgdb.Conversation {
	pg := h.pg
	if m, err := pg.GetIMSession(platform, chatID); err == nil && m != nil {
		if c, err := pg.GetConversation(m.ConversationID); err == nil && c != nil {
			return c
		}
	}
	agentKey := h.AgentKey(cfg)
	title := "IM · " + platform
	if userID != "" {
		title += " · " + userID
	}
	nc, err := pg.CreateConversation(agentKey, title, nil)
	if err != nil {
		log.Printf("[im %s/%s] 开会话失败: %v", platform, chatID, err)
		h.Reply(platform, chatID, "开会话失败："+err.Error())
		return nil
	}
	if err := pg.UpsertIMSession(platform, chatID, nc.ID, userID); err != nil {
		log.Printf("[im %s/%s] 会话映射失败: %v", platform, chatID, err)
	}
	note := "会话由 IM（" + platform + "）创建。\n/bond 绑定项目/任务；/commands 看全部指令。"
	_, _ = pg.AppendConvActivity(nc.ID, pgdb.Activity{
		Worker: agentKey, Kind: "text", Summary: FirstLine(note, 200), Detail: note})
	return nc
}

// handleCommand 处理斜杠命令，返回要发回 IM 的文本。/new 会轮换映射到新会话。
func (h *Hub) handleCommand(pg *pgdb.DB, platform, chatID, userID string, conv *pgdb.Conversation, cmd ChatCommand) string {
	switch cmd.Name {
	case "bond":
		return ApplyBondCommand(pg, conv.ID, cmd.Args)
	case "commands", "help":
		return CommandHelp()
	case "new":
		nc, err := CreateSuccessorConversation(pg, conv)
		if err != nil {
			return "创建新会话失败：" + err.Error()
		}
		_ = pg.UpsertIMSession(platform, chatID, nc.ID, userID)
		note := SuccessorNote(pg, conv)
		_, _ = pg.AppendConvActivity(nc.ID, pgdb.Activity{
			Worker: nc.AgentKey, Kind: "text", Summary: FirstLine(note, 200), Detail: note})
		_ = pg.TouchConversation(conv.ID)
		_ = pg.TouchConversation(nc.ID)
		return note
	default: // 形似指令但未知：回清单，避免打错字被静默喂给 LLM
		return "未知指令 " + cmd.Raw + "。\n\n" + CommandHelp()
	}
}

// agentTurn 跑一轮 agent 对话并收集最终回复。busy 控制、user 活动落库、运行
// 链路与增量收集都在宿主（TurnRunner，对齐 4zrec imAgentTurn 的完整语义），
// 与 web 对话页共用同一套状态。
func (h *Hub) agentTurn(conv *pgdb.Conversation, text string) string {
	if h.runner == nil {
		return "IM 对话链路未就绪。"
	}
	return h.runner.RunTurn(conv, text)
}

// LatestActivityID 取该会话最新活动的 id（增量收集回复的起点）。
func LatestActivityID(pg *pgdb.DB, convID int64) int64 {
	rows, _, err := pg.ConvActivityPage(convID, 0, 1)
	if err != nil || len(rows) == 0 {
		return 0
	}
	return rows[0].ID
}

// CollectReply 从 before 之后的活动里取最终回复：优先本轮的 result（agent 终答，
// Detail 是完整 markdown），退而取最后的 text（含出错说明）。
func CollectReply(pg *pgdb.DB, convID, before int64) string {
	rows, _, err := pg.ConvActivityList(convID, before, 500)
	if err != nil {
		return "读取回复失败：" + err.Error()
	}
	var resultID, textID int64
	var textSummary string
	for _, a := range rows {
		switch a.Kind {
		case "result":
			resultID = a.ID
		case "text":
			textID = a.ID
			textSummary = a.Summary
		}
	}
	id, fallback := resultID, ""
	if id == 0 {
		id, fallback = textID, textSummary
	}
	if id == 0 {
		return "（本轮没有产出回复）"
	}
	detail, err := pg.ConvActivityDetail(convID, id)
	if err != nil {
		return "读取回复失败：" + err.Error()
	}
	if strings.TrimSpace(detail) == "" {
		detail = fallback
	}
	if strings.TrimSpace(detail) == "" {
		return "（本轮没有产出回复）"
	}
	return detail
}

// Reply 把文本发回 IM 聊天。各平台的发送差异在适配器里；失败只记日志（IM 侧
// 用户会自己重发，没有可靠的重试队列前不做投递引擎）。
func (h *Hub) Reply(platform, chatID, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	cfg := h.LoadConfig()
	ctx := context.Background()
	var err error
	switch platform {
	case "telegram":
		err = h.imTelegramSend(ctx, cfg, chatID, text)
	case "feishu":
		err = h.imFeishuSend(ctx, cfg, chatID, text)
	case "dingtalk":
		err = h.imDingtalkSend(ctx, cfg, chatID, text)
	case "wecom":
		err = h.imWecomSend(ctx, cfg, chatID, text)
	default:
		err = fmt.Errorf("im: 未知平台 %s", platform)
	}
	if err != nil {
		log.Printf("[im %s/%s] 发送失败: %v", platform, chatID, err)
	}
}

// StopAll 停掉全部平台循环（进程关闭时由 context 取消，无需额外调用；
// 这里保留给配置热更时的全停场景）。
func (h *Hub) StopAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for platform, cancel := range h.cancels {
		cancel()
		delete(h.cancels, platform)
	}
}

// FirstLine 返回单行、限长的预览（summary 用；与宿主侧 firstLine 同实现）。
func FirstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len([]rune(s)) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return s
}
