package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
	"github.com/c1ayooo/4zreco/internal/docpreview"
)

// 文档预览（v0.4.21）：Word/Excel/PPT/PDF 取样渲染成图片，供任务证据卡与
// 报告使用。预览是 sidecar 文件（artifacts/previews/<id>/page-N.jpg），
// 不重复入库、不计入 100 个附件限额；单独按任务 100MB 上限保护。
const (
	maxPreviewPages      = docpreview.DefaultPages
	maxTaskPreviewBytes  = 100 << 20
	previewQueueCapacity = 64
)

// ensurePreviewWorker 懒启动单 worker。LibreOffice 转换并发会抢 profile 锁，
// 所以整个进程只跑一个转换（队列串行），慢但稳定。
func (s *Server) ensurePreviewWorker() {
	s.previewOnce.Do(func() {
		s.previewQ = make(chan int64, previewQueueCapacity)
		go func() {
			for id := range s.previewQ {
				s.generateArtifactPreview(id)
			}
		}()
	})
}

// enqueueArtifactPreview 把文档附件排进预览队列。force=true 用于手动重试，
// 会覆盖已 ready 的预览；默认跳过已 ready/pending 的记录。
func (s *Server) enqueueArtifactPreview(a *db.TaskArtifact, force bool) {
	if a == nil || a.ID <= 0 || !docpreview.Supports(a.Name) {
		return
	}
	// 只跳过已就绪的；pending 必须继续投递——新附件在 Insert 前就标了 pending，
	// 若这里把 pending 当“已排队”就会永远卡住（v0.4.22 实测）。真正的重复投递
	// 由下面的 previewIDs 在途表挡住。
	if !force && a.PreviewState == "ready" {
		return
	}
	pg := s.m.PG()
	if pg == nil {
		return
	}
	s.ensurePreviewWorker()
	s.previewMu.Lock()
	if s.previewIDs == nil {
		s.previewIDs = make(map[int64]bool)
	}
	if s.previewIDs[a.ID] {
		s.previewMu.Unlock()
		return
	}
	s.previewIDs[a.ID] = true
	s.previewMu.Unlock()
	_ = pg.SetTaskArtifactPreview(a.ID, "pending", 0, "")
	go func() {
		defer func() {
			s.previewMu.Lock()
			delete(s.previewIDs, a.ID)
			s.previewMu.Unlock()
		}()
		select {
		case s.previewQ <- a.ID:
		case <-time.After(5 * time.Second):
			_ = pg.SetTaskArtifactPreview(a.ID, "failed", 0, "预览队列繁忙，请稍后手动重试")
		}
	}()
}

// recoverPendingPreviews 服务启动时把上次进程退出前没做完的预览重新排队
// （v0.4.23）。否则 pending 记录会一直停在“生成中”。
func (s *Server) recoverPendingPreviews() {
	pg := s.m.PG()
	if pg == nil {
		return
	}
	list, err := pg.ListPendingPreviewArtifacts()
	if err != nil || len(list) == 0 {
		return
	}
	log.Printf("[artifact-preview] 恢复 %d 个未完成预览", len(list))
	for i := range list {
		s.enqueueArtifactPreview(&list[i], false)
	}
}

// generateArtifactPreview 执行实际转换（worker 串行调用）。
func (s *Server) generateArtifactPreview(id int64) {
	pg := s.m.PG()
	if pg == nil {
		return
	}
	a, err := pg.GetTaskArtifact(id)
	if err != nil || a == nil {
		return
	}
	if !docpreview.Supports(a.Name) {
		_ = pg.SetTaskArtifactPreview(id, "skipped", 0, "非文档类型，无需预览")
		return
	}
	if s.taskPreviewBytes(a.TaskID) > maxTaskPreviewBytes {
		_ = pg.SetTaskArtifactPreview(id, "skipped", 0, "本任务预览图总量已达上限（100MB），可清理后重试")
		return
	}
	src := filepath.Join(s.m.dir, a.Storage)
	outDir := s.previewDir(a.TaskID, id)
	pages, err := docpreview.Generate(context.Background(), src, outDir, maxPreviewPages)
	if err != nil {
		state, msg := "failed", err.Error()
		if errors.Is(err, docpreview.ErrSofficeMissing) || errors.Is(err, docpreview.ErrPdftoppmMissing) {
			state = "skipped"
			msg += "；请在一键安装或「宿主环境」页安装 libreoffice + poppler-utils"
		}
		_ = pg.SetTaskArtifactPreview(id, state, 0, msg)
		log.Printf("[artifact-preview] #%d %s: %v", id, a.Name, err)
		return
	}
	_ = pg.SetTaskArtifactPreview(id, "ready", pages, "")
}

func (s *Server) previewDir(taskID string, artifactID int64) string {
	return filepath.Join(s.taskArtifactsDir(taskID), "previews", strconv.FormatInt(artifactID, 10))
}

// taskPreviewBytes 统计该任务已生成的预览图总量（避免无上限占盘）。
func (s *Server) taskPreviewBytes(taskID string) int64 {
	root := filepath.Join(s.taskArtifactsDir(taskID), "previews")
	var total int64
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// serveArtifactPreview 提供预览页（page-1.jpg…）：图片内联，可缓存。
func (s *Server) serveArtifactPreview(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil || aid <= 0 {
		writeErr(w, 400, "bad artifact id")
		return
	}
	page, err := strconv.Atoi(r.PathValue("page"))
	if err != nil || page <= 0 {
		writeErr(w, 400, "bad page")
		return
	}
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	a, err := pg.GetTaskArtifact(aid)
	if err != nil || a == nil || a.TaskID != taskID {
		writeErr(w, 404, "artifact not found")
		return
	}
	if a.PreviewState != "ready" || page > a.PreviewPages {
		writeErr(w, 404, "preview not ready")
		return
	}
	file := filepath.Join(s.previewDir(taskID, aid), fmt.Sprintf("page-%d.jpg", page))
	if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "preview file missing")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeFile(w, r, file)
}

// regenerateArtifactPreview 手动重试（或首次生成）文档预览。
func (s *Server) regenerateArtifactPreview(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil || aid <= 0 {
		writeErr(w, 400, "bad artifact id")
		return
	}
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	a, err := pg.GetTaskArtifact(aid)
	if err != nil || a == nil || a.TaskID != taskID {
		writeErr(w, 404, "artifact not found")
		return
	}
	if !docpreview.Supports(a.Name) {
		writeErr(w, 400, "该附件不是文档类型，无需生成预览")
		return
	}
	s.enqueueArtifactPreview(a, true)
	writeJSON(w, 202, map[string]any{"state": "pending", "artifact_id": aid})
}
