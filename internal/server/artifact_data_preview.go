package server

// 数据文件在线查看（移植自上游 v0.4.41）：task_artifacts 里 json/csv/txt/log 类
// 数据证据此前只能下载、无法在页面上看——「把数据扒下来展示」的关键缺口。
// 这里把数据文件解析成结构化预览（JSON 数组→表格行、CSV/TSV→表格、
// JSONL→逐行、其余→文本），前端 ArtifactDataViewer 直接渲染。
//
// 限额：读入 ≤20MB（与单附件上限一致），JSON 行/CSV 行/文本行各自封顶，
// 超出在响应里标 truncated——证据原文永远可以走 download 拿全量。

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreco/internal/db"
)

const (
	dataPreviewMaxBytes = 20 << 20
	dataPreviewMaxRows  = 100
	dataPreviewMaxLines = 200
	dataPreviewMaxValue = 300
)

func dataPreviewKind(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	switch ext {
	case "gz":
		return "gz"
	case "zip":
		return "zip"
	case "json":
		return "json"
	case "jsonl", "ndjson":
		return "jsonl"
	case "csv":
		return "csv"
	case "tsv":
		return "tsv"
	default:
		return "text"
	}
}

// dataParseResult 是解析后的预览负载。
type dataParseResult struct {
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	BoundFinding int64    `json:"bound_finding"`
	TotalRows    int      `json:"total_rows"`
	Truncated    bool     `json:"truncated"`
	Columns      []string `json:"columns,omitempty"`
	Rows         [][]any  `json:"rows,omitempty"`
	Text         string   `json:"text,omitempty"`
	TotalSize    int64    `json:"total_size"`
	Envelope     string   `json:"envelope,omitempty"`
}

func parseDataPreview(kind, raw string) *dataParseResult {
	switch kind {
	case "json":
		return parseJSONPreview(raw)
	case "jsonl":
		return parseJSONLPreview(raw)
	case "csv", "tsv":
		return parseCSVPreview(raw, kind)
	default:
		return parseTextPreview(raw)
	}
}

func parseJSONPreview(raw string) *dataParseResult {
	res := &dataParseResult{Type: "json"}
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &v); err != nil {
		return parseTextPreview(raw)
	}
	// API 信封下钻：{code,msg,data:[...]} 这类响应自动取数组字段作为
	// 行来源（data/rows/list/result/records 优先）。
	if obj, ok := v.(map[string]any); ok {
		for _, k := range []string{"data", "rows", "list", "result", "records"} {
			if inner, ok2 := obj[k].([]any); ok2 && len(inner) > 0 {
				res2 := parseJSONPreviewItems(inner)
				res2.Envelope = k
				res2.TotalRows = len(inner)
				res2.Truncated = len(inner) > dataPreviewMaxRows
				return res2
			}
		}
	}
	switch arr := v.(type) {
	case []any:
		*res = *parseJSONPreviewItems(arr)
		res.TotalRows = len(arr)
		res.Truncated = len(arr) > dataPreviewMaxRows
	case map[string]any:
		res.TotalRows = 1
		keys := []string{}
		for k := range arr {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		res.Columns = keys
		cells := make([]any, 0, len(keys))
		for _, k := range keys {
			cells = append(cells, clipValue(arr[k]))
		}
		res.Rows = append(res.Rows, cells)
	default:
		res.Text = strings.TrimSpace(raw)
	}
	return res
}

// dataRowCells 把一条记录摊成与 columns 对齐的单元格；新键遇到时补齐已有行。
func dataRowCells(item any, cols *[]string, colSet map[string]bool) []any {
	obj, ok := item.(map[string]any)
	if !ok {
		return []any{clipValue(item)}
	}
	for k := range obj {
		if !colSet[k] && len(*cols) < 30 {
			colSet[k] = true
			*cols = append(*cols, k)
		}
	}
	cells := make([]any, 0, len(*cols))
	for _, c := range *cols {
		if v, ok := obj[c]; ok {
			cells = append(cells, clipValue(v))
		} else {
			cells = append(cells, nil)
		}
	}
	return cells
}

func clipValue(v any) any {
	s, ok := v.(string)
	if !ok {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		s = string(b)
	}
	s = strings.TrimSpace(s)
	if len(s) > dataPreviewMaxValue {
		s = s[:dataPreviewMaxValue] + "…"
	}
	return s
}

// parseJSONPreviewItems 把数组元素摊成表格行（与 []any 分支共用列收集逻辑）。
func parseJSONPreviewItems(arr []any) *dataParseResult {
	res := &dataParseResult{Type: "json"}
	colSet := map[string]bool{}
	n := len(arr)
	if n > dataPreviewMaxRows {
		n = dataPreviewMaxRows
	}
	for _, item := range arr[:n] {
		if obj, ok := item.(map[string]any); ok {
			for k := range obj {
				if !colSet[k] && len(colSet) < 30 {
					colSet[k] = true
				}
			}
		}
	}
	cols := make([]string, 0, len(colSet))
	for k := range colSet {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	res.Columns = cols
	for _, item := range arr[:n] {
		res.Rows = append(res.Rows, dataRowCells(item, &cols, colSet))
	}
	return res
}

func parseJSONLPreview(raw string) *dataParseResult {
	res := &dataParseResult{Type: "jsonl"}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	colSet := map[string]bool{}
	cols := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		res.TotalRows++
		if len(res.Rows) >= dataPreviewMaxRows {
			res.Truncated = true
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			res.Rows = append(res.Rows, []any{clipValue(line)})
			continue
		}
		res.Rows = append(res.Rows, dataRowCells(obj, &cols, colSet))
	}
	res.Columns = cols
	return res
}

func parseCSVPreview(raw string, kind string) *dataParseResult {
	res := &dataParseResult{Type: "csv"}
	sep := ','
	if kind == "tsv" {
		sep = '\t'
	}
	r := csv.NewReader(strings.NewReader(raw))
	r.Comma = sep
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		return parseTextPreview(raw)
	}
	res.Columns = records[0]
	body := records[1:]
	res.TotalRows = len(body)
	res.Truncated = len(body) > dataPreviewMaxRows
	for i, rec := range body {
		if i >= dataPreviewMaxRows {
			break
		}
		cells := make([]any, 0, len(rec))
		for _, c := range rec {
			cells = append(cells, strings.TrimSpace(c))
		}
		res.Rows = append(res.Rows, cells)
	}
	return res
}

func parseTextPreview(raw string) *dataParseResult {
	res := &dataParseResult{Type: "text"}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	// 去掉末尾的空行（文件以换行结束是常态，不该算作第 N 行）。
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	res.TotalRows = len(lines)
	res.Truncated = len(lines) > dataPreviewMaxLines
	keep := lines
	if len(keep) > dataPreviewMaxLines {
		keep = keep[:dataPreviewMaxLines]
	}
	res.Text = strings.Join(keep, "\n")
	return res
}

func (s *Server) serveArtifactDataPreview(w http.ResponseWriter, r *http.Request) {
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
	abs := filepath.Join(s.m.dir, a.Storage)
	st, err := os.Stat(abs)
	if err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "artifact file missing")
		return
	}
	raw, innerName, zipRes, err := expandArtifact(abs, a.Name)
	if err != nil {
		writeErr(w, 500, "解析失败: "+err.Error())
		return
	}
	var res *dataParseResult
	if zipRes != nil {
		res = zipRes
	} else {
		res = parseDataPreview(dataPreviewKind(innerName), raw)
	}
	res.TotalSize = st.Size()
	res.Name = a.Name
	res.Kind = a.Kind
	res.BoundFinding = a.FindingID
	writeJSON(w, 200, res)
}

// v0.4.42 扩展（随移植一并纳入）：gzip 解包、zip 目录、xml/yaml/sql/html 当文本——
// 更多文件类型能被「主动转化」成可读形态。

// innerPreviewName 剥掉 .gz 后缀，返回解包后的真实文件名。
func innerPreviewName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".gz")
}

// expandArtifact 读取文件并按需解包：.gz 自动 gunzip；.zip 返回条目清单。
// 返回 (内容, 内层文件名, zip条目, 错误)。
func expandArtifact(abs string, name string) (string, string, *dataParseResult, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", "", nil, err
	}
	defer f.Close()
	if strings.HasSuffix(strings.ToLower(name), ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return "", "", nil, err
		}
		defer zr.Close()
		raw, err := io.ReadAll(io.LimitReader(zr, dataPreviewMaxBytes))
		if err != nil {
			return "", "", nil, err
		}
		return string(raw), innerPreviewName(name), nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, dataPreviewMaxBytes))
	if err != nil {
		return "", "", nil, err
	}
	if strings.HasSuffix(strings.ToLower(name), ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(raw), st64(abs))
		if err != nil {
			// 不是合法 zip → 当文本
			return string(raw), name, nil, nil
		}
		res := &dataParseResult{Type: "zip", Columns: []string{"文件名", "大小", "修改时间"}}
		res.TotalRows = len(zr.File)
		res.Truncated = len(zr.File) > dataPreviewMaxRows
		n := len(zr.File)
		if n > dataPreviewMaxRows {
			n = dataPreviewMaxRows
		}
		for _, zf := range zr.File[:n] {
			mt := zf.Modified.Format("2006-01-02 15:04")
			res.Rows = append(res.Rows, []any{zf.Name, fmtBytes64(zf.UncompressedSize64), mt})
		}
		return "", name, res, nil
	}
	return string(raw), name, nil, nil
}

func fmtBytes64(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func st64(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

// isDataPreviewArtifact 判断附件是否值得走数据预览：图片/文档已有各自的
// 展示路径（img / docpreview 取样页），其余按扩展名能解析成数据/文本的都算。
func isDataPreviewArtifact(a *db.TaskArtifact) bool {
	if a == nil || a.Kind == "image" {
		return false
	}
	if isDocArtifactName(a.Name) || a.Kind == "document" || a.Kind == "spreadsheet" ||
		a.Kind == "presentation" || a.Kind == "pdf" {
		return false
	}
	switch a.Kind {
	case "data", "log", "html", "other", "auto":
		return true
	}
	switch dataPreviewKind(a.Name) {
	case "json", "jsonl", "csv", "tsv", "text", "gz", "zip":
		return true
	}
	return false
}

// isDocArtifactName 按扩展名判断是否文档类附件（与前端 isDoc 口径一致）。
func isDocArtifactName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".odt", ".ods", ".odp", ".csv", ".rtf",
		".ppt", ".pptx":
		return true
	}
	return false
}
