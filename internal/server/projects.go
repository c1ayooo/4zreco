package server

import (
	"net/http"
	"strings"
	"unicode/utf8"
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
	if err := pg.Projects().DeleteProject(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// DB 侧 FK 已置空；内存里的任务快照同步解除挂载（不然 DTO 显示旧项目直到重启）。
	s.m.DetachProjectFromTasks(id)
	writeJSON(w, 200, map[string]any{"ok": true})
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
