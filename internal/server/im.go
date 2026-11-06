package server

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/imhub"
)

// im.go IM 交互机器人的 server 侧薄接线。协议帧编解码、平台长连接、命令集、
// 会话映射都在 internal/imhub 包；这里只做四件事：
//  1. 装配钩子 startIMHub（装配块 newNotifier 之后调用，对齐 4zrec 的启动位置）；
//  2. 企微回调路由（Handler() 注册，requireAuth 豁免，端点内部自验签）；
//  3. settings API 的 im_bot 分支（回显/保存，保存即热重起收发循环）；
//  4. 对话驱动链接线：imTurnRunner 把 IM 消息接进 conversations.go 的
//     runConversationTurn（busy 表与 web 对话页共用），web 分流在
//     pgSendConversationMessage（与 IM 共用同一套斜杠命令）。

// imTurnMaxWait 是 IM 触发的 agent 轮的独立等待上限（盘点 adaptations-b 第二条
// 缓解）。IM 是同步交互通道，用户没有 web 那样的停止按钮：hitl_mode=eino 时轮
// 可能 park 等审批（缺省 hitlAskDefaultTimeout=6h），不设上限用户只能干等。取
// 30 分钟的依据：内置 agent 的 run_seconds 种子默认 1200s（db.go seedBuiltins），
// 正常轮在此之内自然完成、上限不触发；审批 ask 固化的 AskTimeoutSeconds 是秒级，
// 正常审批也不受影响——被截断的只有审批 park 长挂与 run_seconds=0（pentest 不
// 限时）的超长轮。
const imTurnMaxWait = 30 * time.Minute

// imTurnWaitExceeded 是等待上限触发时挂在取消 context 上的具名原因
// （agent/cancelcause.go 的取消点登记约定），Chat 落中断活动时展示给用户。
var imTurnWaitExceeded = agent.Causef("im_turn_wait_exceeded", "IM 对话轮等待超时",
	"IM 触发的对话轮超过 %s 的独立等待上限，agent 运行被中止。已产生的活动记录保留；"+
		"如触达需人工审批的操作，请到 Web 端审批处理后续跑", imTurnMaxWait)

// startIMHub 在 Server 装配时启动已启用平台的收发循环（feishu/dingtalk/telegram；
// 企微无常驻循环，入站走 HTTP 回调）。
func (s *Server) startIMHub() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	s.imHub = imhub.New(s.ctx, s.m.pg, imTurnRunner{s})
	s.imHub.BaseURL = func() string { return notifyPublicBaseURL(s.m.pg) }
	// HITL 差异（4zrec 没有的新语义）：hitl_mode=eino 时 Chat 轮可能 park 等审批
	// （最长 hitlAskDefaultTimeout），IM 是同步阻塞收最终回复——等待期间只有这条
	// 回执，文案提示去 web 审批页。channel 模式（默认灰度缺省）保持原文案。
	s.imHub.AckNote = func() string {
		if s.engine != nil && s.engine.hitlEnabled() {
			return "收到，正在处理…（如触达需人工审批的操作，请到 Web 端「系统 → 审批拦截」处理）"
		}
		return ""
	}
	s.imHub.Start()
}

// imTurnRunner 实现 imhub.TurnRunner。
type imTurnRunner struct{ s *Server }

// RunTurn 一轮 IM 触发的 agent 对话，busy 控制、user 活动落库、运行链路与增量
// 收集对齐 4zrec im_hub.go 的 imAgentTurn——与 web 对话页共用同一张 busy 表
// （key "conv-<id>"），同一会话上互相排队。
func (r imTurnRunner) RunTurn(conv *db.Conversation, text string) string {
	s := r.s
	pg := s.m.pg
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		return "这个会话正在处理上一条消息，请稍候再发。"
	}
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	defer func() {
		s.chatMu.Lock()
		delete(s.chatBusy, busyKey)
		s.chatMu.Unlock()
	}()

	before := imhub.LatestActivityID(pg, conv.ID)
	ua := db.Activity{Worker: conv.AgentKey, Kind: "user", Summary: imhub.FirstLine(text, 200), Detail: text}
	if _, err := pg.AppendConvActivity(conv.ID, ua); err != nil {
		log.Printf("[im conv %d] append user msg failed: %v", conv.ID, err)
	}
	_ = pg.TouchConversation(conv.ID)
	// 与 runConversationSync 相同的两步，只在中间包一层独立等待上限：
	// conversationRunContext 注册 chatCancel（web 停止按钮仍可中止本轮），
	// tctx 的 deadline 到点以 imTurnWaitExceeded 收口——Chat 落「运行被中断」
	// 活动（含已生成的部分输出），CollectReply 取到后回给 IM，busy 随之释放。
	// runConversationTurn 的签名本就接受外部 ctx 来源（runConversation 与
	// runConversationSync 各传一套），共享链路零改动。
	ctx, cancel := s.conversationRunContext(conv.ID, busyKey)
	defer cancel(agent.AbortChatTurnFinished) // 外层（chatCancel 注册的）由 runner 收口
	tctx, tstop := context.WithTimeoutCause(ctx, imTurnMaxWait, imTurnWaitExceeded)
	tcancel := context.CancelCauseFunc(func(error) { tstop() })
	s.runConversationTurn(tctx, tcancel, conv, text, busyKey)
	return imhub.CollectReply(pg, conv.ID, before)
}

// imWecomCallback 是企微回调路由的薄转发（协议处理在 imhub）。
func (s *Server) imWecomCallback(w http.ResponseWriter, r *http.Request) {
	if s.imHub == nil {
		writeErr(w, 404, "IM 接入未就绪")
		return
	}
	s.imHub.WecomCallback(w, r)
}

// imBotPayload 是 settings 回显里 im_bot 的部分（组包在 imhub：凭据只回 *_set，
// 明文不出服务端）。
func (s *Server) imBotPayload() map[string]any {
	if s.imHub == nil {
		return map[string]any{}
	}
	return s.imHub.Payload()
}

// handleConversationCommand 处理 web 对话页的一条斜杠指令并把指令+回复落进
// 对话流（分流点在 pgSendConversationMessage，对齐 4zrec conversations.go:422-425）。
func (s *Server) handleConversationCommand(w http.ResponseWriter, pg *db.DB, c *db.Conversation, msg string) {
	cmd, _ := imhub.ParseChatCommand(msg)
	if cmd.Name == "new" {
		s.handleNewConversationCommand(w, pg, c, msg)
		return
	}
	reply := imhub.CommandHelp()
	switch cmd.Name {
	case "bond":
		reply = imhub.ApplyBondCommand(pg, c.ID, cmd.Args)
	case "commands", "help":
	default: // 形似指令但未知：回复清单，避免打错字被静默喂给 LLM
		reply = "未知指令 " + cmd.Raw + "。\n\n" + imhub.CommandHelp()
	}
	imhub.AppendCommandExchange(pg, c, msg, reply)
	_ = pg.TouchConversation(c.ID)
	writeJSON(w, 200, map[string]any{"status": "handled"})
}

// handleNewConversationCommand 开新会话：旧会话不落任何记录（保持干净），说明性
// 回复写进新会话；响应带 new_conversation_id，前端收到后可切换过去。
func (s *Server) handleNewConversationCommand(w http.ResponseWriter, pg *db.DB, c *db.Conversation, msg string) {
	nc, err := imhub.CreateSuccessorConversation(pg, c)
	if err != nil {
		imhub.AppendCommandExchange(pg, c, msg, "创建新会话失败："+err.Error())
		_ = pg.TouchConversation(c.ID)
		writeJSON(w, 200, map[string]any{"status": "handled"})
		return
	}
	note := imhub.SuccessorNote(pg, c)
	_, _ = pg.AppendConvActivity(nc.ID, db.Activity{
		Worker: c.AgentKey, Kind: "text", Summary: imhub.FirstLine(note, 200), Detail: note})
	_ = pg.TouchConversation(nc.ID)
	writeJSON(w, 200, map[string]any{"status": "handled", "new_conversation_id": nc.ID})
}
