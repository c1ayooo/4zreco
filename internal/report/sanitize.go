package report

import (
	"strings"
	"unicode/utf8"
)

// cleanText 让任意来源的文本可以安全写进 UTF-8 产物（Markdown / OOXML）：
//   - 非法 UTF-8 字节序列替换为 U+FFFD，避免下游按编码猜测时整段乱码；
//   - 去掉 XML 1.0 不允许的控制字符（\x00-\x08、\x0B、\x0C、\x0E-\x1F、\x7F），
//     否则 Word 会以「内容有问题」告警或静默丢字。
//
// 制表/换行/回车保留。幂等。
func cleanText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
}

// truncateUTF8 把 s 截到不超过 maxBytes 字节，且不切断多字节字符。
// 按字节截断会把一个汉字的 UTF-8 序列劈成两半，得到非法 UTF-8——zip 因此
// 不置 UTF-8 标志位，Windows/WinRAR 按 CP437/GBK 解码就成乱码。
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
