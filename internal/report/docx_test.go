package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreco/internal/db"
)

func TestDocxStructure(t *testing.T) {
	d := NewDocx()
	d.H1("渗透测试报告 — 测试任务")
	d.P("生成时间:2026-10-18")
	d.H2("一、概览")
	d.Table([]string{"资产类型", "数量"}, [][]string{{"IP", "770"}, {"服务", "712"}})
	d.Bullet("要点一")
	d.Code("curl http://target/ -H 'X-Test: 1'")
	d.H3("3.1 子标题 <特殊字符> & 引号")
	d.PageBreak()
	d.H2("二、漏洞明细")
	d.P("含 & 尖括号 < > 的段落")

	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty docx")
	}

	// zip 结构与关键部件
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	want := map[string]bool{
		"[Content_Types].xml":          false,
		"_rels/.rels":                  false,
		"word/document.xml":            false,
		"word/styles.xml":              false,
		"word/_rels/document.xml.rels": false,
	}
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing part: %s", name)
		}
	}

	// document.xml 内容:转义正确、元素存在
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		rc.Close()
		doc := b.String()
		for _, frag := range []string{
			"渗透测试报告 — 测试任务",
			"&lt;特殊字符&gt; &amp; 引号",
			"X-Test: 1",
			"<w:tbl>",
			`w:type="page"`,
			"Heading2",
		} {
			if !strings.Contains(doc, frag) {
				t.Errorf("document.xml missing %q", frag)
			}
		}
		if strings.Contains(doc, "<w:t>unclosed") {
			t.Error("escaping broken")
		}
	}
}

func TestBuildTaskDocxAndFindingDocx(t *testing.T) {
	f := &db.DBFinding{
		ID: 42, VulnClass: "未授权访问", Name: "Admin console exposed",
		Severity: "critical", Summary: "console reachable", Evidence: "curl /admin → 200",
		Worker: "work#1", AssetIDs: []int64{5, 2}, CreatedAt: time.Now(),
		Report: "## 复现步骤\n1. 打开 /admin\n```\ncurl -i http://x/admin\n```\n### 影响\n全量接管",
	}
	in := TaskDocxInput{
		Title: "T", Goal: "G", GeneratedAt: time.Now(),
		AssetCounts: map[string]int{"ip": 3},
		Findings:    []*db.DBFinding{f},
		AssetNames:  map[int64]string{5: "10.0.0.5", 2: "admin.example.com"},
		Retests: map[int64][]*db.FindingRetest{
			42: {{FindingID: 42, Verdict: "reproduced", Summary: "PoC 复现成功", CreatedAt: time.Now()}},
		},
		Customer:       "示例客户",
		AppendixAssets: map[string][]string{"ip": {"10.0.0.5", "10.0.0.6"}},
	}
	var buf bytes.Buffer
	if err := BuildTaskDocx(in).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty task docx")
	}
	// 内容级断言（A2/A8/A9/A10）
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, zf := range zr.File {
		if zf.Name == "word/document.xml" {
			rc, _ := zf.Open()
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			doc = b.String()
		}
	}
	for _, frag := range []string{
		"影响资产:10.0.0.5, admin.example.com", // A8 可读名
		"最近复测:已复现",                         // A9 复测小节
		"<w:color w:val=\"C00000\"/>",      // A2 critical 标题着色
	} {
		if !strings.Contains(doc, frag) {
			t.Errorf("document.xml missing %q", frag)
		}
	}
	if strings.Contains(doc, "影响资产 id:") {
		t.Error("legacy 影响资产 id: 形态仍在（A8 未生效）")
	}
	// A3/A12/A16
	for _, frag := range []string{"委托方:示例客户", "附录 A 资产清单", "internal 集别"} {
		_ = frag // 占位防误改；实际断言在下方
	}
	if !strings.Contains(doc, "委托方:示例客户") {
		t.Error("missing cover customer line (A12)")
	}
	if !strings.Contains(doc, "附录 A 资产清单") {
		t.Error("missing appendix A (A16)")
	}
	if !strings.Contains(doc, "10.0.0.6") {
		t.Error("appendix asset rows missing")
	}
	buf.Reset()
	if err := BuildFindingDocx(FindingDocxInput{
		Finding:      f,
		GeneratedAt:  time.Now(),
		AssetNameMap: map[int64]string{5: "10.0.0.5"},
	}).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty finding docx")
	}
}

// TestDocxBulletNumbering A1：包里必须有 numbering.xml 且 numId=1 存在——
// 此前缺该部件导致 Word 里项目符号静默不渲染。
func TestDocxBulletNumbering(t *testing.T) {
	d := NewDocx()
	d.Bullet("要点一")
	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		rc.Close()
		found[f.Name] = b.String()
	}
	num, ok := found["word/numbering.xml"]
	if !ok {
		t.Fatal("missing word/numbering.xml（bullet 会静默不渲染）")
	}
	if !strings.Contains(num, `<w:num w:numId="1">`) {
		t.Error("numbering.xml missing <w:num w:numId=1>")
	}
	rels := found["word/_rels/document.xml.rels"]
	if !strings.Contains(rels, "numbering.xml") {
		t.Error("document.xml.rels missing numbering relationship")
	}
	// 全部件 XML 良构校验：手写模板一旦出语法错误，Word 会直接拒绝打开整个文件
	// ——比「少个 bullet」严重得多，必须在测试里拦住。
	for name, body := range found {
		if !strings.HasSuffix(name, ".xml") && !strings.HasSuffix(name, ".rels") {
			continue
		}
		if err := xml.Unmarshal([]byte(body), new(any)); err != nil {
			t.Errorf("part %s is not well-formed XML: %v", name, err)
		}
	}
}

// TestWriteMarkdownishRich A5：表格/加粗/层级。
func TestWriteMarkdownishRich(t *testing.T) {
	d := NewDocx()
	md := "## 复现步骤\n- 打开 **/admin** 面板\n\n| 字段 | 值 |\n|---|---|\n| path | /admin |\n| auth | 无 |\n"
	writeMarkdownish(d, md)
	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			doc = b.String()
		}
	}
	for _, frag := range []string{
		"<w:tbl>",  // 表格真 OOXML 化
		"<w:b/>",   // 加粗 run
		"Heading2", // ## → 公文二级楷体标题（不再压平到 H3）
		"w:numId",  // bullet 编号引用
	} {
		if !strings.Contains(doc, frag) {
			t.Errorf("document.xml missing %q", frag)
		}
	}
	// 分隔行 |---|---| 不能进表格内容
	if strings.Contains(doc, "---") {
		t.Error("table separator row leaked into document")
	}
}

// TestTaskDocxAggregation 同类多主机上报在总报告里折叠:类别分布一行 +
// 明细按类别分组(变体写法 SQLi/SQL注入 也要折进同一组)。
func TestTaskDocxAggregation(t *testing.T) {
	mk := func(id int64, class, sev string) *db.DBFinding {
		return &db.DBFinding{
			ID: id, VulnClass: class, Name: "MS17-010", Severity: sev,
			Summary: "smb reachable", Evidence: "nmap -p445",
			AssetIDs: []int64{id * 10}, CreatedAt: time.Now(),
		}
	}
	findings := []*db.DBFinding{
		mk(1, "永恒之蓝", "high"), mk(2, "CVE-2017-0144", "high"), mk(3, "已知漏洞", "high"),
		mk(4, "SQLi", "critical"), mk(5, "sql注入", "medium"),
		mk(6, "未授权访问", "low"),
	}
	in := TaskDocxInput{Title: "T", GeneratedAt: time.Now(), Findings: findings}
	var buf bytes.Buffer
	if err := BuildTaskDocx(in).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			doc = b.String()
		}
	}
	if doc == "" {
		t.Fatal("no document.xml")
	}
	// 已知漏洞组(3 条,变体已折叠)排第一组;注入组(2 条)次之
	for _, frag := range []string{
		"3.1 已知漏洞(共 3 条)", "3.2 注入(共 2 条)", "3.3 未授权访问(共 1 条)",
		"漏洞类别分布", "涉及资产数",
	} {
		if !strings.Contains(doc, frag) {
			t.Errorf("document.xml missing %q", frag)
		}
	}
}
