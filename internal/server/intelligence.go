package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/c1ayooo/4zreco/internal/db"
)

// 任务情报 HTTP 面（C2，移植自 ARTEX 0.3.29）。
//
// 范围授权对齐本地任务继承规则（db.intelligenceScope）：task_relations 直接继承
// 来源任务可见；仅共享同一资产不授予任何任务溯源（ARTEX 同款语义）。资产维度路由
// 只按 asset_ids 命中镜像同一份数据。

func intelligenceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrIntelligenceInvalid):
		writeErr(w, 400, err.Error())
	case errors.Is(err, db.ErrIntelligenceNotFound):
		writeErr(w, 404, "情报不存在或不属于当前范围")
	default:
		writeErr(w, 500, err.Error())
	}
}

// intelligenceFilter 解析列表/详情请求的 scope 与过滤参数。scope 由路由包装层经
// SetPathValue("scope","assets") 注入；任务/资产存在性在此统一校验。
func (s *Server) intelligenceFilter(w http.ResponseWriter, r *http.Request) (db.IntelligenceFilter, bool) {
	f := db.IntelligenceFilter{}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效 ID")
		return f, false
	}
	if r.PathValue("scope") == "assets" {
		f.AssetID = id
	} else {
		f.TaskID = id
	}
	var exists bool
	if f.TaskID > 0 {
		err = s.m.pg.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, id).Scan(&exists)
	} else {
		err = s.m.pg.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1)`, id).Scan(&exists)
	}
	if err != nil {
		intelligenceError(w, err)
		return f, false
	}
	if !exists {
		writeErr(w, 404, "任务或资产不存在")
		return f, false
	}
	q := r.URL.Query()
	f.Kind = q.Get("kind")
	f.Status = q.Get("status")
	f.Query = q.Get("q")
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if len(f.Query) > 500 {
		writeErr(w, 400, "搜索关键词过长")
		return f, false
	}
	return f, true
}

func (s *Server) listIntelligence(w http.ResponseWriter, r *http.Request) {
	f, ok := s.intelligenceFilter(w, r)
	if !ok {
		return
	}
	page, err := s.m.pg.ListIntelligence(r.Context(), f)
	if err != nil {
		intelligenceError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, page)
}

func (s *Server) getIntelligence(w http.ResponseWriter, r *http.Request) {
	f, ok := s.intelligenceFilter(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("intelID"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效情报 ID")
		return
	}
	item, err := s.m.pg.GetIntelligence(r.Context(), id)
	if err != nil {
		intelligenceError(w, err)
		return
	}
	allowed := false
	if f.TaskID > 0 {
		err = s.m.pg.QueryRowContext(r.Context(), `SELECT $1::bigint=$2::bigint OR EXISTS(SELECT 1 FROM task_relations WHERE task_id=$1 AND source_task_id=$2)`, f.TaskID, item.TaskID).Scan(&allowed)
	} else {
		for _, assetID := range item.AssetIDs {
			if assetID == f.AssetID {
				allowed = true
			}
		}
	}
	if err != nil {
		intelligenceError(w, err)
		return
	}
	if !allowed {
		intelligenceError(w, db.ErrIntelligenceNotFound)
		return
	}
	item.Inherited = f.TaskID > 0 && item.TaskID != f.TaskID
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, item)
}

// updateIntelligence 人工定级。继承来的情报只读（task_id 不匹配 → 404，db 层把关）。
func (s *Server) updateIntelligence(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, 400, "无效任务 ID")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("intelID"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效情报 ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		Status string `json:"status"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "无效请求")
		return
	}
	if err := s.m.pg.UpdateIntelligenceStatus(r.Context(), taskID, id, req.Status); err != nil {
		intelligenceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"updated": true})
}
