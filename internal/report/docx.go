// Package report 的 docx 子模块:手写的最小 OOXML(.docx)生成器。
// 不引入第三方文档库——.docx 本质是 zip + XML,报告需要的元素(标题层级/
// 段落/列表/表格/分页)用一小段生成器即可覆盖,换来:零新依赖、单二进制哲学
// 不破、输出结构完全可控(内置中文报告模板的字体/字号/表格边框都在 styles.xml)。
package report

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"
)

// Docx 是一份正在组装的文档;方法按顺序追加元素。
type Docx struct {
	buf        bytes.Buffer
	headerText string      // 页眉文字（SetHeaderText；空 = 默认「渗透测试报告」）
	fonts      []docxFont  // 嵌入字体（EmbedFont；Encode 时混淆成 odttf 打包）
	images     []docxImage // 报告插图（Image；Encode 时打包进 word/media）
	// artifactImage 解析 Markdown 里的 ![说明](artifact:<id>)（host 注入：
	// 从任务证据附件库取图片字节与图注）。nil = 不支持内嵌图片。
	artifactImage func(id int64) (data []byte, caption string, ok bool)
}

// docxFont 一个待嵌入字体：OOXML 字体名 + TTF 原始字节。
type docxFont struct {
	name string
	ttf  []byte
}

// EmbedFont 把一个 TTF 注册进文档，Encode 时混淆打包。公文三字体
// （仿宋_GB2312/楷体_GB2312/方正小标宋_GBK）在新版 Windows、Linux 均不自带，
// 不嵌入时 Word 静默 fallback 成宋体——行盒与字形全变（用户实测「行距全不对」
// 的另一半根因）。嵌入后接收方无需装字体即可原样渲染。
func (d *Docx) EmbedFont(name string, ttf []byte) {
	d.fonts = append(d.fonts, docxFont{name: name, ttf: ttf})
}

// obfuscateFont 生成 ECMA-376 odttf 混淆体与 fontKey：随机 GUID，TTF 前 32
// 字节与 GUID 的 16 个字节按下标 15-(i%16) 倒序循环异或（docx4j / OpenXML SDK
// 同款算法）；Word/WPS 打开时按 fontKey 反解。返回 fontKey 形如 {XXXXXXXX-...}。
func obfuscateFont(ttf []byte) (data []byte, key string) {
	var g [16]byte
	_, _ = rand.Read(g[:])
	g[6] = g[6]&0x0f | 0x40 // version 4
	g[8] = g[8]&0x3f | 0x80 // variant 10
	key = fmt.Sprintf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
	out := make([]byte, len(ttf))
	copy(out, ttf)
	for i := 0; i < 32 && i < len(out); i++ {
		out[i] ^= g[15-i%16]
	}
	return out, key
}

// NewDocx 建立空文档(自动加封面后的第一个标题也由调用方控制)。
func NewDocx() *Docx { return &Docx{} }

// SetArtifactImageResolver 注入证据附件图片解析器（v0.5.0）。
func (d *Docx) SetArtifactImageResolver(fn func(id int64) ([]byte, string, bool)) {
	d.artifactImage = fn
}

var xmlEsc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func esc(s string) string { return xmlEsc.Replace(s) }

// H1/H2/H3 标题。
func (d *Docx) H1(text string) { d.heading(text, 1) }
func (d *Docx) H2(text string) { d.heading(text, 2) }
func (d *Docx) H3(text string) { d.heading(text, 3) }

func (d *Docx) heading(text string, level int) {
	fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:pStyle w:val="Heading%d"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, level, esc(text))
}

// headingColored 带标题色的标题（严重度着色用：critical 红/high 橙/medium 琥珀/low 蓝）。
func (d *Docx) headingColored(text string, level int, hex string) {
	fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:pStyle w:val="Heading%d"/></w:pPr><w:r><w:rPr><w:color w:val="%s"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, level, hex, esc(text))
}

// H4 四级标题（漏洞明细内的小节：报告正文里的 ## 降到这里，不再压平）。
func (d *Docx) H4(text string) { d.heading(text, 4) }

// Run 富文本片段（PRich 用）。
type Run struct {
	Text string
	Bold bool
	Code bool // 内联代码（`x`）：Consolas 字体区分
}

// PRich 富文本段落：支持 **加粗** 级别（Markdown 富渲染 A5 的底层）。\n 拆多段。
func (d *Docx) PRich(text string) {
	for _, line := range strings.Split(text, "\n") {
		d.buf.WriteString(`<w:p>`)
		d.buf.WriteString(runsXML(parseRich(line)))
		d.buf.WriteString(`</w:p>`)
	}
}

// parseRich 在 **加粗** 之上再支持 `内联代码`（Consolas 字体区分，v0.4.0）：
// reporter 正文大量 `POST /path`、`totalRows` 标记，原样输出反引号很难读。
func parseRich(line string) []Run {
	var out []Run
	rest := line
	for {
		i := strings.Index(rest, "`")
		if i < 0 {
			break
		}
		if i > 0 {
			out = append(out, parseBold(rest[:i])...)
		}
		rest = rest[i+1:]
		j := strings.Index(rest, "`")
		if j < 0 {
			out = append(out, Run{Text: "`"})
			break
		}
		out = append(out, Run{Text: rest[:j], Code: true})
		rest = rest[j+1:]
	}
	if len(rest) > 0 || len(out) == 0 {
		out = append(out, parseBold(rest)...)
	}
	return out
}

// parseBold 把一行按 **bold** 拆成 Run 序列。不成对的 ** 按字面处理。
func parseBold(line string) []Run {
	var runs []Run
	rest := line
	bold := false
	for {
		i := strings.Index(rest, "**")
		if i < 0 {
			break
		}
		if i > 0 {
			runs = append(runs, Run{Text: rest[:i], Bold: bold})
		}
		rest = rest[i+2:]
		bold = !bold
	}
	if rest != "" || len(runs) == 0 {
		runs = append(runs, Run{Text: rest, Bold: bold})
	}
	return runs
}

func runsXML(runs []Run) string {
	var b strings.Builder
	for _, r := range runs {
		var props []string
		if r.Bold {
			props = append(props, "<w:b/>")
		}
		if r.Code {
			props = append(props, `<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>`)
		}
		rpr := ""
		if len(props) > 0 {
			rpr = "<w:rPr>" + strings.Join(props, "") + "</w:rPr>"
		}
		fmt.Fprintf(&b, `<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>`, rpr, esc(r.Text))
	}
	return b.String()
}

// P 正文段落(支持 \n 拆多段)。
func (d *Docx) P(text string) {
	for _, line := range strings.Split(text, "\n") {
		fmt.Fprintf(&d.buf, `<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(line))
	}
}

// Code 等宽代码块(证据/PoC 用):底纹+左竖线、Consolas、保留空白。
// 整段合并为一个段落（行间用 w:br）——逐行成段会让长 JSON 被拆成上百个
// 独立段落、视觉散成一片（Kali 用户实测「全堆到一块儿」的主因之一）。
func (d *Docx) Code(text string) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var b strings.Builder
	b.WriteString(`<w:p><w:pPr><w:pStyle w:val="Code"/></w:pPr>`)
	for i, line := range lines {
		if i > 0 {
			b.WriteString(`<w:r><w:br/></w:r>`)
		}
		fmt.Fprintf(&b, `<w:r><w:t xml:space="preserve">%s</w:t></w:r>`, esc(line))
	}
	b.WriteString(`</w:p>`)
	d.buf.WriteString(b.String())
}

// Hei1 公文一级标题：黑体三号、首行缩进 2 字符（如「一、评估概览」）。
func (d *Docx) Hei1(text string) {
	d.buf.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(text)))
}

// Kai2 公文二级标题：楷体三号、首行缩进 2 字符（如「（一）复现步骤」）。
func (d *Docx) Kai2(text string) {
	d.buf.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(text)))
}

// Bullet 无序列表项。
func (d *Docx) Bullet(text string) {
	// ind firstLine=0：清 Normal 的公文首行缩进，缩进交给 numbering 定义
	fmt.Fprintf(&d.buf, `<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr><w:ind w:firstLine="0"/><w:jc w:val="both"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, esc(text))
}

// Table 带表头的表格。rows 与 header 列数不一致时按最短补齐。
func (d *Docx) Table(header []string, rows [][]string) {
	d.TableFills(header, rows, nil)
}

// TableFills 带行底色的表格：fills[i] 是第 i 行数据的底色 hex（空串或越界 = 无底色）。
// 严重度分布表按严重度着色用（A2）。
func (d *Docx) TableFills(header []string, rows [][]string, fills []string) {
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/></w:tblPr><w:tblGrid>`)
	for range header {
		b.WriteString(`<w:gridCol w:w="1800"/>`)
	}
	b.WriteString(`</w:tblGrid>`)
	// 单元格文字 10pt：正文字号升到三号后，表格若继承会巨大变形
	cell := func(text, fill string) {
		sty := ""
		if fill != "" {
			sty = fmt.Sprintf(`<w:shd w:val="clear" w:fill="%s"/>`, fill)
		}
		fmt.Fprintf(&b, `<w:tc><w:tcPr>%s</w:tcPr><w:p><w:pPr><w:spacing w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0"/></w:pPr><w:r><w:rPr><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`, sty, esc(text))
	}
	b.WriteString(`<w:tr>`)
	for _, h := range header {
		cell(h, "DEEAF6")
	}
	b.WriteString(`</w:tr>`)
	for ri, r := range rows {
		b.WriteString(`<w:tr>`)
		fill := ""
		if ri < len(fills) {
			fill = fills[ri]
		}
		for i := range header {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			cell(v, fill)
		}
		b.WriteString(`</w:tr>`)
	}
	b.WriteString(`</w:tbl>`)
	// OOXML 要求表格后跟一个空段落
	b.WriteString(`<w:p/>`)
	d.buf.WriteString(b.String())
}

// PageBreak 分页。
func (d *Docx) PageBreak() {
	d.buf.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
}

// coverLineSpacing 封面行行距：二号字（≥20pt，封面文件标题）用 35 磅——
// 28 磅 exact 装不下二号字，Word/LibreOffice 会把字形上下裁切（用户实测
// 「行距全不对」的主因之一，GB/T 9704 实务定版：标题行距 35 磅）；其余 28 磅。
func coverLineSpacing(sz int) string {
	line := 560
	if sz >= 40 {
		line = 700
	}
	return fmt.Sprintf(`<w:spacing w:before="120" w:after="0" w:line="%d" w:lineRule="exact"/>`, line)
}

// CoverLine 封面行：居中、可指定半点字号（sz）与颜色。空文本输出空行（撑版面用）。
func (d *Docx) CoverLine(text string, sz int, bold bool) {
	// 覆盖 Normal 的两端对齐/首行缩进/28 磅行距——封面行居中、行距独立控制。
	spacing := coverLineSpacing(sz)
	if text == "" {
		spacing = `<w:spacing w:before="0" w:after="0" w:line="720" w:lineRule="exact"/>`
	}
	pPr := fmt.Sprintf(`<w:pPr>%s<w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>`, spacing)
	if text == "" {
		fmt.Fprintf(&d.buf, `<w:p>%s</w:p>`, pPr)
		return
	}
	rpr := "<w:rPr>"
	if bold {
		// 公文文件标题：方正小标宋二号、不加粗（GB/T 9704 7.3.3 标题定版；
		// 字体随文档嵌入，接收方无此字体也原样渲染）
		rpr += `<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="方正小标宋_GBK"/><w:b w:val="0"/>`
	}
	if sz > 0 {
		rpr += fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, sz, sz)
	}
	rpr += "</w:rPr>"
	fmt.Fprintf(&d.buf, `<w:p>%s<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r></w:p>`, pPr, rpr, esc(text))
}

// CoverLineColored 带色的封面行（单漏洞封面按严重度着色用）。
func (d *Docx) CoverLineColored(text string, sz int, hex string, bold bool) {
	// 与 CoverLine 同版式（居中/清缩进/行距覆盖，二号标题 35 磅）；公文标题
	// 小标宋不加粗，ascii 统一 Times New Roman。
	boldXML := ""
	if bold {
		boldXML = `<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="方正小标宋_GBK"/><w:b w:val="0"/>`
	} else {
		boldXML = `<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="仿宋_GB2312"/><w:b w:val="0"/>`
	}
	szXML := ""
	if sz > 0 {
		szXML = fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, sz, sz)
	}
	fmt.Fprintf(&d.buf,
		`<w:p><w:pPr>%s<w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr><w:r><w:rPr>%s<w:color w:val="%s"/>%s</w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		coverLineSpacing(sz), boldXML, hex, szXML, esc(text))
}

// TOC 目录字段：Word 打开时按 updateFields 设置自动刷新（settings.xml 已置
// updateFields，见 Encode）。\o "1-3" 收 Heading1-3——H4（漏洞明细小节）不进目录。
func (d *Docx) TOC() {
	d.buf.WriteString(`<w:p><w:fldSimple w:instr=" TOC \o &quot;1-3&quot; \h \z \u ">` +
		`<w:r><w:t>（在 Word 中按 F9 或打印预览可刷新目录）</w:t></w:r></w:fldSimple></w:p>`)
}

// Encode 打包成 .docx 字节流。
func (d *Docx) Encode(w io.Writer) error {
	// 页眉页脚引用走 r: 命名空间（headerReference/footerReference 的 r:id）。
	// 页面设置对齐公文参考件：页边距 上2098/右1474/下1984/左1587，docGrid 360。
	// 公文无页眉——headerReference 已移除，页码走页脚「— N —」。
	document := `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body>` +
		d.buf.String() +
		`<w:sectPr>` +
		`<w:footerReference w:type="default" r:id="rIdFtr"/>` +
		`<w:pgSz w:w="11906" w:h="16838"/>` +
		`<w:pgMar w:top="2098" w:right="1474" w:bottom="1984" w:left="1587" w:header="720" w:footer="720" w:gutter="0"/>` +
		// docGrid 580：GB/T 9704 版心 225mm÷每面 22 行 ≈ 29 磅/行的行网格
		// （参考件的 360 是 Word 默认 18 磅网格，与 22 行规格不符）。
		`<w:cols w:space="720"/><w:docGrid w:linePitch="580"/>` +
		`</w:sectPr></w:body></w:document>`

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`
	if len(d.images) > 0 {
		contentTypes += `
<Default Extension="png" ContentType="image/png"/>
<Default Extension="jpg" ContentType="image/jpeg"/>
<Default Extension="gif" ContentType="image/gif"/>`
	}
	if len(d.fonts) > 0 {
		// odttf 的 content type：官方 MIME（Word 自产嵌入文档同款）——
		// 写 application/octet-stream 时 Word 直接判「文件损坏」拒开。
		contentTypes += `
<Default Extension="odttf" ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/>
<Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>`
	}
	contentTypes += "\n</Types>"

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

	// numbering.xml：Bullet 引用 numId=1——此前包里没有这个部件，Word 里项目符号
	// 静默不渲染（v0.3.93 A1，报告质感的显性 bug）。
	// styles.xml 的 relationship 此前同样缺失——Word 拿不到样式部件，整个公文
	// 样式体系（仿宋_GB2312 正文/首行缩进/28 磅固定行距/标题字体）从未生效，
	// 全部按 Word 默认等线渲染（用户实测「行距全不对」的总根因，v0.4.4 修复）。
	documentRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
<Relationship Id="rIdSty" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rIdFtr" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
<Relationship Id="rIdSet" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>`
	for _, img := range d.images {
		documentRels += fmt.Sprintf(`
<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/%s"/>`, img.rid, img.name)
	}
	if len(d.fonts) > 0 {
		documentRels += `
<Relationship Id="rIdFT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>`
	}
	documentRels += "\n</Relationships>"

	// settings.xml：embedTrueTypeFonts 声明内嵌字体；updateFields 让 Word 打开
	// 文档时自动刷新 TOC/PAGE 等字段。（schema 顺序要求 embedTrueTypeFonts 在
	// updateFields 之前，顺序错 Word 会报文档损坏。）
	settings := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
` + func() string {
		if len(d.fonts) > 0 {
			return "<w:embedTrueTypeFonts/>"
		}
		return ""
	}() + `
<w:updateFields w:val="true"/>
</w:settings>`

	// 公文页码：页脚居中「— N —」（4 号半角宋体数字、两侧一字线），无页眉。
	footer := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:p><w:pPr><w:jc w:val="center"/></w:pPr>
<w:r><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr><w:t xml:space="preserve">— </w:t></w:r>
<w:r><w:fldChar w:fldCharType="begin"/></w:r>
<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>
<w:r><w:fldChar w:fldCharType="end"/></w:r>
<w:r><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr><w:t xml:space="preserve"> —</w:t></w:r>
</w:p>
</w:ftr>`

	zw := zip.NewWriter(w)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + document},
		{"word/_rels/document.xml.rels", documentRels},
		{"word/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + docxStyles},
		{"word/numbering.xml", numbering()},
		{"word/settings.xml", settings},
		{"word/footer1.xml", footer},
	}
	// 报告插图：word/media/imageN.ext（关系已在 document.xml.rels 里）。
	for _, img := range d.images {
		fw, err := zw.Create("word/media/" + img.name)
		if err != nil {
			return err
		}
		if _, err := fw.Write(img.data); err != nil {
			return err
		}
	}
	// 嵌入字体：fontTable.xml（字体名 → odttf 关系 + fontKey）与每字体的
	// word/fonts/fontN.odttf（其关系表 word/_rels/fontTable.xml.rels）。
	if len(d.fonts) > 0 {
		var fontDecls, fontRels strings.Builder
		for i, f := range d.fonts {
			data, key := obfuscateFont(f.ttf)
			fw, err := zw.Create(fmt.Sprintf("word/fonts/font%d.odttf", i+1))
			if err != nil {
				return err
			}
			if _, err := fw.Write(data); err != nil {
				return err
			}
			rid := fmt.Sprintf("rIdF%d", i+1)
			fontDecls.WriteString(fmt.Sprintf(
				`<w:font w:name="%s"><w:charset w:val="86"/><w:family w:val="auto"/><w:pitch w:val="variable"/><w:embedRegular r:id="%s" w:fontKey="%s"/></w:font>`,
				esc(f.name), rid, key))
			fmt.Fprintf(&fontRels,
				`<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/font" Target="fonts/font%d.odttf"/>`,
				rid, i+1)
		}
		files = append(files,
			struct{ name, body string }{"word/fontTable.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` + fontDecls.String() + `</w:fonts>`},
			struct{ name, body string }{"word/_rels/fontTable.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + fontRels.String() + `</Relationships>`},
		)
	}
	for _, f := range files {
		fw, err := zw.Create(f.name)
		if err != nil {
			return err
		}
		if _, err := io.Copy(fw, strings.NewReader(f.body)); err != nil {
			return err
		}
	}
	return zw.Close()
}

// SetHeaderText 自定义页眉文字（客户名/报告名）。须在 Encode 前调用。
func (d *Docx) SetHeaderText(text string) { d.headerText = text }

// numbering numbering.xml 部件：numId=1 → bullet 项目符号（Bullet 方法引用它）。
func numbering() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:abstractNum w:abstractNumId="0">
<w:multiLevelType w:val="hybridMultilevel"/>
<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Symbol" w:hAnsi="Symbol" w:hint="default"/></w:rPr></w:lvl>
<w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="o"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="1440" w:hanging="360"/></w:pPr></w:lvl>
<w:lvl w:ilvl="2"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="&#61623;"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="2160" w:hanging="360"/></w:pPr></w:lvl>
</w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>`
}

// docxNum 部件按需打包；headerText 经由 Docx 字段透传。

// docxStyles 内置中文公文风样式（GB/T 9704 风格取舍）：
// 正文仿宋三号（16pt）、首行缩进 2 字符、固定行距 28 磅；
// 一级标题黑体三号、二级黑体四号、三/四级黑体小四；
// 代码 Consolas 小五紧排+底纹。Heading1 大纲级别 0（Word 导航窗格可见）。
const docxStyles = `<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="仿宋_GB2312"/>
<w:b w:val="0"/><w:color w:val="000000"/>
<w:sz w:val="32"/><w:szCs w:val="32"/>
</w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:styleId="Normal" w:default="1"><w:name w:val="Normal"/>
<w:pPr><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/>
<w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="0"/><w:spacing w:before="120" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="黑体"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="1"/><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="楷体_GB2312"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="2"/><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="黑体"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/>
<w:pPr><w:outlineLvl w:val="3"/><w:spacing w:before="0" w:after="0" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="640"/><w:jc w:val="both"/></w:pPr>
<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="黑体"/><w:b w:val="0"/><w:color w:val="000000"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="60" w:after="60" w:line="240" w:lineRule="auto"/>
<w:ind w:left="240" w:firstLine="0"/><w:jc w:val="left"/>
<w:shd w:val="clear" w:fill="F7F7F7"/>
<w:pBdr><w:left w:val="single" w:sz="12" w:space="4" w:color="BFBFBF"/></w:pBdr></w:pPr>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="宋体"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/>
<w:tblPr><w:tblBorders>
<w:top w:val="single" w:sz="4" w:color="999999"/><w:left w:val="single" w:sz="4" w:color="999999"/>
<w:bottom w:val="single" w:sz="4" w:color="999999"/><w:right w:val="single" w:sz="4" w:color="999999"/>
<w:insideH w:val="single" w:sz="4" w:color="999999"/><w:insideV w:val="single" w:sz="4" w:color="999999"/>
</w:tblBorders></w:tblPr></w:style>
</w:styles>`

// SeverityHex 严重度主色（标题/表格底色用，A2）。
func SeverityHex(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "C00000" // 深红
	case "high":
		return "ED7D31" // 橙
	case "medium":
		return "BF9000" // 琥珀
	case "low":
		return "5B9BD5" // 蓝
	default:
		return ""
	}
}

// SeverityHexSoft 严重度柔和底色（表格行底色用，比主色浅）。
func SeverityHexSoft(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "F8CBCC"
	case "high":
		return "FBE5D5"
	case "medium":
		return "FFF2CC"
	case "low":
		return "DEEAF6"
	default:
		return ""
	}
}

// SeverityCN 严重度中文映射(报告用)。
func SeverityCN(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "严重(critical)"
	case "high":
		return "高危(high)"
	case "medium":
		return "中危(medium)"
	case "low":
		return "低危(low)"
	default:
		return s
	}
}

// FormatTimeUTC 统一时间展示(UTC,报告里避免时区歧义)。
func FormatTimeUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
