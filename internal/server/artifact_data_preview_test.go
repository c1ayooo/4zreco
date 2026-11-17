package server

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

// v0.4.41 移植：数据文件预览解析——JSON 数组/对象/JSONL/CSV/文本 五类形态。
// 解析函数与上游 server/artifact_data_preview_test.go 同款对照。
func TestParseJSONPreviewArray(t *testing.T) {
	raw := `[{"order":"A1","amount":100},{"order":"A2","amount":200},{"order":"A3","amount":300}]`
	r := parseJSONPreview(raw)
	if r.Type != "json" || r.TotalRows != 3 || r.Truncated {
		t.Fatalf("meta=%+v", r)
	}
	if len(r.Columns) != 2 || r.Columns[0] != "amount" || r.Columns[1] != "order" {
		t.Fatalf("columns=%v", r.Columns)
	}
	if len(r.Rows) != 3 || r.Rows[0][1] != "A1" {
		t.Fatalf("rows=%v", r.Rows)
	}
}

func TestParseJSONPreviewObjectAndFallback(t *testing.T) {
	r := parseJSONPreview(`{"code":"200","msg":"ok"}`)
	if r.Type != "json" || r.TotalRows != 1 || len(r.Columns) != 2 {
		t.Fatalf("object meta=%+v", r)
	}
	// 非法 JSON → 退回文本
	r2 := parseJSONPreview("不是 JSON 的内容")
	if r2.Type != "text" || !strings.Contains(r2.Text, "不是 JSON") {
		t.Fatalf("fallback=%+v", r2)
	}
}

func TestParseJSONLAndCSV(t *testing.T) {
	jl := "{\"user\":\"u1\"}\n{\"user\":\"u2\"}\n\n"
	r := parseJSONLPreview(jl)
	if r.TotalRows != 2 || len(r.Rows) != 2 || r.Columns[0] != "user" {
		t.Fatalf("jsonl=%+v", r)
	}
	csvRaw := "name,role\nalice,admin\nbob,user\n"
	rc := parseCSVPreview(csvRaw, "csv")
	if rc.TotalRows != 2 || len(rc.Columns) != 2 || rc.Rows[0][0] != "alice" {
		t.Fatalf("csv=%+v", rc)
	}
	tsv := "a\tb\n1\t2\n"
	rt := parseCSVPreview(tsv, "tsv")
	if len(rt.Columns) != 2 || rt.Rows[0][1] != "2" {
		t.Fatalf("tsv=%+v", rt)
	}
}

func TestParseTextPreviewTruncates(t *testing.T) {
	lines := make([]string, dataPreviewMaxLines+50)
	for i := range lines {
		lines[i] = "line"
	}
	r := parseTextPreview(strings.Join(lines, "\n"))
	if r.Type != "text" || !r.Truncated || r.TotalRows != dataPreviewMaxLines+50 {
		t.Fatalf("meta=%+v", r)
	}
	if got := strings.Count(r.Text, "\n") + 1; got != dataPreviewMaxLines {
		t.Fatalf("text lines=%d want %d", got, dataPreviewMaxLines)
	}
}

// API 信封 {code,msg,data:[...]} 自动下钻到 data 数组（生产最常见的响应形态）。
func TestParseJSONPreviewEnvelope(t *testing.T) {
	raw := `{"code":"200","msg":"ok","data":[{"order":"A1","amount":100},{"order":"A2","amount":200}]}`
	r := parseJSONPreview(raw)
	if r.Envelope != "data" {
		t.Fatalf("envelope=%q want data", r.Envelope)
	}
	if r.TotalRows != 2 || len(r.Rows) != 2 || r.Rows[0][1] != "A1" {
		t.Fatalf("rows=%v", r.Rows)
	}
}

func TestDataPreviewKindExt(t *testing.T) {
	cases := map[string]string{
		"a.json": "json", "b.jsonl": "jsonl", "c.csv": "csv", "d.tsv": "tsv",
		"e.gz": "gz", "f.zip": "zip", "g.xml": "text", "h.yaml": "text",
		"i.sql": "text", "j.log": "text", "k.md": "text", "l.txt": "text",
		"m.out": "text", "n.diff": "text",
	}
	for name, want := range cases {
		if got := dataPreviewKind(name); got != want {
			t.Errorf("kind(%q)=%q want %q", name, got, want)
		}
	}
}

func TestParseGZDataset(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "orders.json.gz")
	f, _ := os.Create(p)
	zw := gzip.NewWriter(f)
	_, _ = zw.Write([]byte(`[{"k":"v1"},{"k":"v2"}]`))
	zw.Close()
	f.Close()

	raw, inner, zipRes, err := expandArtifact(p, "orders.json.gz")
	if err != nil || zipRes != nil {
		t.Fatalf("expand err=%v zipRes=%v", err, zipRes)
	}
	if inner != "orders.json" {
		t.Fatalf("inner=%q want orders.json", inner)
	}
	res := parseDataPreview(dataPreviewKind(inner), raw)
	if res.Type != "json" || res.TotalRows != 2 || res.Rows[0][0] != "v1" {
		t.Fatalf("res=%+v", res)
	}
}

func TestIsDataPreviewArtifact(t *testing.T) {
	yes := []string{"dump.json", "scan.log", "out.txt", "resp.gz", "bundle.zip", "page.html"}
	for _, name := range yes {
		if !isDataPreviewArtifact(&db.TaskArtifact{Name: name, Kind: "data"}) {
			t.Errorf("%q should be data-previewable", name)
		}
	}
	no := []struct{ name, kind string }{
		{"shot.png", "image"}, {"report.docx", "document"}, {"table.csv", "spreadsheet"},
		{"scan.pdf", "pdf"}, {"slide.pptx", "presentation"},
	}
	for _, c := range no {
		if isDataPreviewArtifact(&db.TaskArtifact{Name: c.name, Kind: c.kind}) {
			t.Errorf("%q (kind=%s) should not be data-previewable", c.name, c.kind)
		}
	}
}
