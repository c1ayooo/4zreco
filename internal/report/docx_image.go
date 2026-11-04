package report

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"  // DecodeConfig 注册（gif 也允许，转存原格式）
	_ "image/jpeg" // DecodeConfig 注册
	_ "image/png"  // DecodeConfig 注册
)

// docxImage 是一个待嵌入的内联图片（v0.5.0 报告截图）。
// OOXML 里图片是独立 media 部件 + 关系引用，尺寸单位 EMU（1pt=12700EMU，
// 96dpi 下 1px=9525EMU）。按比例缩到版心内，避免截图撑破页面。
type docxImage struct {
	rid     string
	name    string // word/media/ 下的文件名（image1.png）
	data    []byte
	cx, cy  int64 // EMU
	caption string
	seq     int
}

// 版心尺寸（GB/T 9704：156mm × 225mm）；图片留一点边，宽不超过约 144mm。
const (
	maxImageWidthEMU  int64 = 5_200_000 // ≈144.4mm
	maxImageHeightEMU int64 = 7_000_000 // ≈194.4mm
	pxToEMU           int64 = 9525      // 96dpi
)

// Image 嵌入一张图片并输出「居中图片段落 + 居中图注段落」。
// 只接受 Go 标准库能解析尺寸的格式（png/jpeg/gif），失败返回 false 由调用方
// 决定是否降级为文字说明（不因一张坏图让整份报告失败）。
func (d *Docx) Image(data []byte, caption string) bool {
	if len(data) == 0 {
		return false
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 {
		return false
	}
	ext := "png"
	switch format {
	case "jpeg":
		ext = "jpg"
	case "gif":
		ext = "gif"
	}
	w := int64(cfg.Width) * pxToEMU
	h := int64(cfg.Height) * pxToEMU
	if w > maxImageWidthEMU {
		h = h * maxImageWidthEMU / w
		w = maxImageWidthEMU
	}
	if h > maxImageHeightEMU {
		w = w * maxImageHeightEMU / h
		h = maxImageHeightEMU
	}
	n := len(d.images) + 1
	img := docxImage{
		rid: fmt.Sprintf("rIdImg%d", n), name: fmt.Sprintf("image%d.%s", n, ext),
		data: data, cx: w, cy: h, caption: caption, seq: n,
	}
	d.images = append(d.images, img)

	// 图片段落：居中、清首行缩进、行距 auto（exact 会裁图）。
	fmt.Fprintf(&d.buf,
		`<w:p><w:pPr><w:spacing w:before="120" w:after="60" w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>`+
			`<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">`+
			`<wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="图%d" descr="%s"/>`+
			`<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">`+
			`<pic:pic><pic:nvPicPr><pic:cNvPr id="%d" name="%s"/><pic:cNvPicPr/></pic:nvPicPr>`+
			`<pic:blipFill><a:blip r:embed="%s"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>`+
			`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm>`+
			`<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>`+
			`</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`,
		img.cx, img.cy, img.seq, img.seq, esc(caption), img.seq, esc(img.name), img.rid, img.cx, img.cy)
	if caption != "" {
		// 图注：居中、10.5pt（五号）、28 磅行距。
		fmt.Fprintf(&d.buf,
			`<w:p><w:pPr><w:spacing w:before="0" w:after="120" w:line="560" w:lineRule="exact"/><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr>`+
				`<w:r><w:rPr><w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr><w:t xml:space="preserve">图 %d：%s</w:t></w:r></w:p>`,
			n, esc(caption))
	}
	return true
}
