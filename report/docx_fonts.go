package report

import "embed"

// 公文三字体随二进制分发（go:embed）：导出 Word 时自动嵌进文档（odttf），
// 接收方不装字体也能按 GB/T 9704 正确渲染。字体文件名用 ASCII——go:embed
// 的中文路径在跨平台构建/git 检出时不可靠；TTF 内部 family 名（docx 里引用的）
// 仍是 仿宋_GB2312 / 楷体_GB2312 / 方正小标宋_GBK（fc-scan 实测）。
// 版权说明：三字体为用户提供的公文标准字体包，仅随本平台导出的报告分发。
//
//go:embed fonts/fangsong_gb2312.ttf fonts/kaiti_gb2312.ttf fonts/fzxiaobiaosong_gbk.ttf
var gongwenFontFS embed.FS

// embedGongwenFonts 把公文三字体挂到文档上。单字体加载失败只跳过不报错——
// 缺字体时退化为「引用字体名」（接收方装了字体仍正常），不能让整个导出失败。
func embedGongwenFonts(d *Docx) {
	for _, e := range []struct{ name, file string }{
		{"仿宋_GB2312", "fonts/fangsong_gb2312.ttf"},
		{"楷体_GB2312", "fonts/kaiti_gb2312.ttf"},
		{"方正小标宋_GBK", "fonts/fzxiaobiaosong_gbk.ttf"},
	} {
		if b, err := gongwenFontFS.ReadFile(e.file); err == nil {
			d.EmbedFont(e.name, b)
		}
	}
}
