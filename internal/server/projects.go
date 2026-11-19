package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/internal/sidequestion"
)

// ---------- projects (任务/对话的归属主轴) ----------
//
// 项目管理的最小闭环：CRUD + 范围维护。项目范围是组织定义（本项目不接资产
// 围栏），供项目详情展示与建任务时的 task_scope 种子。直接序列化 db.Project
// （conversations 同款先例，无 DTO）。

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	projects, err := pg.Projects().ListProjects()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"projects": projects})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, 400, "项目名称不能为空")
		return
	}
	if utf8.RuneCountInString(name) > 120 {
		writeErr(w, 400, "项目名称最多 120 个字符")
		return
	}
	p, err := pg.Projects().CreateProject(name, strings.TrimSpace(req.Description))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, p)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, 400, "项目名称不能为空")
		return
	}
	if utf8.RuneCountInString(name) > 120 {
		writeErr(w, 400, "项目名称最多 120 个字符")
		return
	}
	status := req.Status
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "archived" {
		writeErr(w, 400, "status 只能为 active 或 archived")
		return
	}
	p, err := pg.Projects().UpdateProject(id, name, strings.TrimSpace(req.Description), status)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		return
	}
	p, err := pg.Projects().GetProject(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p.ID == 0 {
		writeErr(w, 404, "项目不存在")
		return
	}
	taskIDs, err := pg.Projects().ProjectLiveTaskIDs(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	convIDs, err := pg.Projects().ProjectConversationIDs(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	// 任务先删：逐个走完整 teardown（删除屏障 + 主对话取消 + Agent 静默等待 +
	// 级联），与单任务删除端点同一契约——静默等待覆盖建任务后的异步目标拆解，
	// 真正在跑的任务静默超时后按 busy 拒绝。这里用 Background：级联要么删完要么
	// 明确报错，客户端断连不留半个删了一半的项目。归档冷任务不在此列
	// （ProjectLiveTaskIDs 已排除），其归档包保留、仅随项目行解除挂载。
	tasksDeleted := 0
	var warnings []string
	for _, tid := range taskIDs {
		_, err := s.deleteTaskFully(context.Background(), strconv.FormatInt(tid, 10), DeleteTaskOptions{})
		if err != nil {
			var committed *taskDeleteCommittedError
			if errors.As(err, &committed) {
				// DB 已删、仅外部清理未竟：任务视为已删，警告随响应带回。
				tasksDeleted++
				warnings = append(warnings, fmt.Sprintf("#%d：%v", tid, err))
				continue
			}
			msg := fmt.Sprintf("#%d：%v", tid, err)
			if tasksDeleted > 0 {
				// 4xx 文案原样透传给前端，把部分进度说清楚；500 走 writeErr 的
				// U8 脱敏固定文案，丢进度可接受（重试自愈：已删任务退出 live 列表）。
				msg = fmt.Sprintf("已删 %d 个任务后中止：%s", tasksDeleted, msg)
			}
			if status, ok := taskDeleteErrStatus(err); ok {
				writeErr(w, status, msg)
			} else {
				writeErr(w, 500, msg)
			}
			return
		}
		tasksDeleted++
	}

	// 对话：先取消在途 chat 与旁路提问（与批量删除端点同款），再一把删。
	for _, cid := range convIDs {
		s.cancelConversation(cid)
		s.cancelSideWhere(func(p sidequestion.Parent) bool { return p.ConversationID == cid })
	}
	convDeleted, err := pg.DeleteConversations(convIDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	if err := pg.Projects().DeleteProject(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	resp := map[string]any{
		"ok":                    true,
		"tasks_deleted":         tasksDeleted,
		"conversations_deleted": len(convDeleted),
	}
	if len(warnings) > 0 {
		resp["cleanup_warning"] = strings.Join(warnings, "; ")
	}
	writeJSON(w, 200, resp)
}

func (s *Server) addProjectScope(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		return
	}
	var req struct {
		Scope  string `json:"scope"`
		Reason string `json:"reason"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Scope) == "" {
		writeErr(w, 400, "范围内容不能为空")
		return
	}
	p, err := pg.Projects().GetProject(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p.ID == 0 {
		writeErr(w, 404, "项目不存在")
		return
	}
	added, skipped, invalid, errMsgs := pg.Projects().AddProjectScope(id, strings.Split(req.Scope, "\n"), req.Reason)
	updated, err := pg.Projects().GetProject(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"added": added, "skipped": skipped, "invalid": invalid,
		"errors": errMsgs, "project": updated,
	})
}

func (s *Server) deleteProjectScope(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		return
	}
	scopeID, ok := pathInt(r, "sid")
	if !ok {
		return
	}
	if err := pg.Projects().DeleteProjectScope(id, scopeID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
