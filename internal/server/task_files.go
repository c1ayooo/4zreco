package server

import (
	"archive/zip"
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 任务详情只读文件浏览（移植自 ARTEX 0.3.29 A5）：以只读视角浏览
// Data/tasks/<id> 工作目录（agent 的 CWD，含 i<intentID> 意图子目录）。
//
// 安全模型：全部文件系统访问走 os.Root（Go 1.24+）——穿越（..）与非可移植
// 路径在 taskFilePath 先拒一遍，残余风险（symlink 逃逸、任务根本身是
// symlink）由 Root 在 open 时拒绝；任务根经由其父目录（Data 根）打开，任务
// 根自己是 symlink 时同样拦截。整个 handler 只读，无任何写路径。
//
// 意图目录标注：worker 的 CWD 是 tasks/<id>/i<intentID>（agent/worker.go），
// 列目录时把 i<intentID> 映射到探索图 intent 节点的 summary/state，前端展示
// 意图标题与状态徽章。查询走本地探索图（db.ExplorationStore.GetNode），
// ARTEX 同构（其 Store.GetNode 也是探索图）。

const maxTaskFiles = 2000

// taskFileEntry 在 wsEntry（工作空间条目，workspace.go）上补只读浏览特有的
// 标注字段。IntentID>0 表示该目录对应一条探索图意图。
type taskFileEntry struct {
	wsEntry
	Symlink     bool   `json:"symlink"`
	IntentID    int64  `json:"intent_id,omitempty"`
	IntentTitle string `json:"intent_title,omitempty"`
	IntentState string `json:"intent_state,omitempty"`
}

type taskFileListing struct {
	Path      string          `json:"path"`
	Entries   []taskFileEntry `json:"entries"`
	Total     int             `json:"total"`
	Size      int64           `json:"size"`
	Truncated bool            `json:"truncated"`
	Missing   bool            `json:"missing"`
}

// taskFilePath 拒绝不可移植路径与穿越，而不是静默 Clean 掉。真正的文件系统
// 访问全部经 os.Root，这里只做第一道过滤。
func taskFilePath(raw string) (string, error) {
	if raw == "" {
		return ".", nil
	}
	if !fs.ValidPath(raw) || strings.ContainsAny(raw, "\\:\x00") || !filepath.IsLocal(raw) {
		return "", errors.New("invalid path")
	}
	return raw, nil
}

func taskFileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		writeErr(w, 404, "任务文件不可用")
	case errors.Is(err, fs.ErrPermission):
		writeErr(w, 403, "无权访问该任务文件")
	default:
		writeErr(w, 400, "非法路径")
	}
}

// openTaskFiles 打开任务工作目录。root 为 nil 且 ok 时表示任务目录尚不存在
// （列表返回 Missing=true，其余路由 404）。base（Data 根）在返回前关闭：
// OpenRoot 返回的是独立句柄，不受父 Root 关闭影响。读取/流式期间不持任何任务锁。
func (s *Server) openTaskFiles(w http.ResponseWriter, r *http.Request) (*os.Root, *Task, string, bool) {
	id := r.PathValue("id")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
		writeErr(w, 404, "任务文件不可用")
		return nil, nil, "", false
	}
	t, ok := s.m.Task(id)
	if !ok {
		writeErr(w, 404, "任务文件不可用")
		return nil, nil, "", false
	}
	rel, err := taskFilePath(r.URL.Query().Get("path"))
	if err != nil {
		taskFileError(w, err)
		return nil, nil, "", false
	}
	paths := s.m.dirs()
	base, err := os.OpenRoot(paths.Data)
	if err != nil {
		taskFileError(w, err)
		return nil, nil, "", false
	}
	defer base.Close()
	// 任务目录相对名从 Paths 派生（Data/tasks/<id>，paths.go），不手写字面量。
	name, err := filepath.Rel(paths.Data, paths.TaskDir(id))
	if err != nil || !fs.ValidPath(name) {
		taskFileError(w, err)
		return nil, nil, "", false
	}
	info, err := base.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, t, rel, true
	}
	if err != nil {
		taskFileError(w, err)
		return nil, nil, "", false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		taskFileError(w, fs.ErrPermission)
		return nil, nil, "", false
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		taskFileError(w, err)
		return nil, nil, "", false
	}
	return root, t, rel, true
}

func newTaskFileEntry(name string, info fs.FileInfo) taskFileEntry {
	return taskFileEntry{
		wsEntry: wsEntry{Name: path.Base(name), Path: name, Dir: info.IsDir(), Size: info.Size(), MTime: info.ModTime().UnixMilli()},
		Symlink: info.Mode()&os.ModeSymlink != 0,
	}
}

// GET /api/tasks/{id}/files?path=<rel> — 列单层目录；意图目录补标题/状态。
func (s *Server) taskFilesList(w http.ResponseWriter, r *http.Request) {
	root, t, rel, ok := s.openTaskFiles(w, r)
	if !ok {
		return
	}
	out := taskFileListing{Path: rel, Entries: []taskFileEntry{}}
	if rel == "." {
		out.Path = ""
	}
	if root == nil {
		if rel != "." {
			taskFileError(w, fs.ErrNotExist)
			return
		}
		out.Missing = true
		writeJSON(w, 200, out)
		return
	}
	defer root.Close()
	dir, err := root.Open(rel)
	if err != nil {
		taskFileError(w, err)
		return
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		taskFileError(w, err)
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			taskFileError(w, err)
			return
		}
		entry := newTaskFileEntry(path.Join(rel, e.Name()), info)
		if rel == "." && entry.Dir && strings.HasPrefix(e.Name(), "i") && t != nil && t.Store != nil {
			if !s.annotateIntentDir(w, t, e.Name(), &entry) {
				return // 探索图查询失败，已写 500
			}
		}
		out.Entries = append(out.Entries, entry)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return a.Name < b.Name
	})
	writeJSON(w, 200, out)
}

// annotateIntentDir 把 i<intentID> 目录名映射到探索图 intent 节点的标题与状态。
// 返回 false 表示查询失败且已写响应。
func (s *Server) annotateIntentDir(w http.ResponseWriter, t *Task, name string, entry *taskFileEntry) bool {
	id, err := strconv.ParseInt(strings.TrimPrefix(name, "i"), 10, 64)
	if err != nil {
		return true // 非 i<intentID> 命名的目录，不作标注
	}
	node, err := t.Store.GetNode(id)
	if err != nil {
		writeErr(w, 500, "查询意图元数据失败："+err.Error())
		return false
	}
	if node == nil || node.Kind != "intent" {
		return true
	}
	var payload map[string]any
	_ = json.Unmarshal(node.Payload, &payload)
	entry.IntentID, entry.IntentState = id, node.State
	entry.IntentTitle, _ = payload["summary"].(string)
	if entry.IntentTitle == "" {
		entry.IntentTitle, _ = payload["title"].(string)
	}
	if entry.IntentTitle == "" {
		entry.IntentTitle = rawString(node.Payload)
	}
	return true
}

// A bounded min-heap retains the newest entries over the ENTIRE scan, with a
// deterministic path tie-breaker. Counts and bytes always describe all files.
type recentTaskFiles []taskFileEntry

func newerTaskFile(a, b taskFileEntry) bool {
	return a.MTime > b.MTime || (a.MTime == b.MTime && a.Path < b.Path)
}
func (h recentTaskFiles) Len() int           { return len(h) }
func (h recentTaskFiles) Less(i, j int) bool { return newerTaskFile(h[j], h[i]) }
func (h recentTaskFiles) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *recentTaskFiles) Push(x any)        { *h = append(*h, x.(taskFileEntry)) }
func (h *recentTaskFiles) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func scanTaskFiles(r *http.Request, root *os.Root) (taskFileListing, error) {
	out := taskFileListing{Entries: []taskFileEntry{}}
	h := recentTaskFiles{}
	err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		entry := newTaskFileEntry(name, info)
		out.Total++
		out.Size += info.Size()
		if len(h) < maxTaskFiles {
			heap.Push(&h, entry)
		} else if newerTaskFile(entry, h[0]) {
			h[0] = entry
			heap.Fix(&h, 0)
		}
		return nil
	})
	sort.Slice(h, func(i, j int) bool { return newerTaskFile(h[i], h[j]) })
	out.Entries = append(out.Entries, h...)
	out.Truncated = out.Total > maxTaskFiles
	return out, err
}

// GET /api/tasks/{id}/files/all — 全量扫描，返回全部文件的计数/字节与新近
// maxTaskFiles 条（受客户端取消中断）。
func (s *Server) taskFilesAll(w http.ResponseWriter, r *http.Request) {
	root, _, _, ok := s.openTaskFiles(w, r)
	if !ok {
		return
	}
	if root == nil {
		writeJSON(w, 200, taskFileListing{Entries: []taskFileEntry{}, Missing: true})
		return
	}
	defer root.Close()
	out, err := scanTaskFiles(r, root)
	if err != nil {
		taskFileError(w, err)
		return
	}
	writeJSON(w, 200, out)
}

// GET /api/tasks/{id}/files/{read|download|preview}?path=<rel> — 三动作共用
// handler，按 URL 最后一段分发。read 内联文本（限 maxWorkspaceRead，二进制/
// 超大只给标志不给内容）；preview 仅限真实图片（扩展名与魔数必须一致，HTML/
// SVG 永不内联渲染）；download 以附件流式下发。
func (s *Server) taskFilesServe(w http.ResponseWriter, r *http.Request) {
	root, _, rel, ok := s.openTaskFiles(w, r)
	if !ok {
		return
	}
	if root == nil {
		taskFileError(w, fs.ErrNotExist)
		return
	}
	defer root.Close()
	// 先检查再打开，避免阻塞在 FIFO 等特殊文件上。
	info, err := root.Stat(rel)
	if err != nil {
		taskFileError(w, err)
		return
	}
	if !info.Mode().IsRegular() {
		writeErr(w, 400, "不是常规文件")
		return
	}
	f, err := root.Open(rel)
	if err != nil {
		taskFileError(w, err)
		return
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeErr(w, 400, "不是常规文件")
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	switch path.Base(r.URL.Path) {
	case "read":
		writeTextFile(w, rel, f, info.Size())
	case "preview":
		types := map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif"}
		want := types[strings.ToLower(path.Ext(rel))]
		buf := make([]byte, 512)
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			taskFileError(w, err)
			return
		}
		if want == "" || http.DetectContentType(buf[:n]) != want {
			writeErr(w, 415, "不是可预览的图片文件")
			return
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			taskFileError(w, err)
			return
		}
		w.Header().Set("Content-Type", want)
		setFileDisposition(w, "inline", path.Base(rel))
		http.ServeContent(w, r, path.Base(rel), info.ModTime(), f)
	case "download":
		w.Header().Set("Content-Type", "application/octet-stream")
		setFileDisposition(w, "attachment", path.Base(rel))
		http.ServeContent(w, r, path.Base(rel), info.ModTime(), f)
	}
}

// setFileDisposition 按 RFC 5987 写 Content-Disposition（filename* 保非 ASCII
// 文件名，filename 兜底）。与 workspace.go 的 wsDownload 同款拼装，收敛成助手。
func setFileDisposition(w http.ResponseWriter, kind, name string) {
	w.Header().Set("Content-Disposition", kind+"; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
}

// writeTextFile 限制的是读本身，而不仅是前置 stat：运行中的 agent 会在 stat
// 与 read 之间继续追加文件。
func writeTextFile(w http.ResponseWriter, path string, r io.Reader, size int64) {
	result := map[string]any{"path": path, "size": size, "binary": false}
	if size > maxWorkspaceRead {
		result["too_large"], result["binary"] = true, true
		writeJSON(w, 200, result)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r, maxWorkspaceRead+1))
	if err != nil {
		writeErr(w, 500, "读取任务文件失败："+err.Error())
		return
	}
	result["size"] = len(data)
	if len(data) > maxWorkspaceRead {
		result["too_large"], result["binary"] = true, true
	} else if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		result["binary"] = true
	} else {
		result["content"] = string(data)
	}
	writeJSON(w, 200, result)
}

// writeTaskFilesZip 流式写 ZIP：每层目录开一个嵌套 Root；symlink 跳过；每个
// 文件都经 Root 打开。条目直接拷贝进 ZIP 流，不整树驻留内存。
func writeTaskFilesZip(r *http.Request, zw *zip.Writer, root *os.Root, prefix string) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	for {
		entries, err := d.ReadDir(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, e := range entries {
			if err := r.Context().Err(); err != nil {
				return err
			}
			info, err := root.Lstat(e.Name())
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			name := path.Join(prefix, e.Name())
			// ZIP 内的名字必须保持相对且可移植（Windows 解压也要安全）。
			if _, err := taskFilePath(name); err != nil {
				continue
			}
			if info.IsDir() {
				sub, err := root.OpenRoot(e.Name())
				if err != nil {
					return err
				}
				_, err = zw.Create(name + "/")
				if err == nil {
					err = writeTaskFilesZip(r, zw, sub, name)
				}
				sub.Close()
				if err != nil {
					return err
				}
			} else if info.Mode().IsRegular() {
				f, err := root.Open(e.Name())
				if err != nil {
					return err
				}
				header, err := zip.FileInfoHeader(info)
				if err == nil {
					header.Name, header.Method = name, zip.Deflate
					var out io.Writer
					out, err = zw.CreateHeader(header)
					if err == nil {
						_, err = io.Copy(out, f)
					}
				}
				f.Close()
				if err != nil {
					return err
				}
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// GET /api/tasks/{id}/files/archive?path=<dir> — 目录树流式 ZIP 导出（HEAD 只
// 回头）。中途出错时 panic(http.ErrAbortHandler) 掐断连接：绝不把半截 ZIP 当
// 成功的下载交付。
func (s *Server) taskFilesArchive(w http.ResponseWriter, r *http.Request) {
	root, t, rel, ok := s.openTaskFiles(w, r)
	if !ok {
		return
	}
	if root == nil {
		taskFileError(w, fs.ErrNotExist)
		return
	}
	defer root.Close()
	info, err := root.Lstat(rel)
	if err != nil {
		taskFileError(w, err)
		return
	}
	if !info.IsDir() {
		writeErr(w, 400, "不是目录")
		return
	}
	sub, err := root.OpenRoot(rel)
	if err != nil {
		taskFileError(w, err)
		return
	}
	defer sub.Close()
	name := path.Base(rel)
	if rel == "." && t != nil {
		name = fmt.Sprintf("task-%s", t.ID)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	setFileDisposition(w, "attachment", name+".zip")
	if r.Method == http.MethodHead {
		return
	}
	zw := zip.NewWriter(w)
	if err := writeTaskFilesZip(r, zw, sub, ""); err != nil {
		panic(http.ErrAbortHandler)
	}
	if err := zw.Close(); err != nil {
		panic(http.ErrAbortHandler)
	}
}
