package report

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/c1ayooo/4zreco/internal/db"
)

// TestCleanText 控制/非法字符清洗：XML 控制字符剔除、制表换行保留、
// 非法 UTF-8 换 U+FFFD、幂等。
func TestCleanText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"剔除 NUL 与 XML 禁字符", "a\x00b\x01c\x0bd\x0ce\x1ff\x7fg", "abcdefg"},
		{"保留制表/换行/回车", "a\tb\nc\r\nd", "a\tb\nc\r\nd"},
		{"中文原样保留", "SQL注入：'单引号'\"双引号\"", "SQL注入：'单引号'\"双引号\""},
		{"非法 UTF-8 换 U+FFFD", "ab\xffc", "ab\uFFFDc"},
		{"截断的汉字（劈开的多字节序列）", "安全\x9c测试", "安全\uFFFD测试"},
		{"空串", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cleanText(c.in)
			if got != c.want {
				t.Fatalf("cleanText(%q) = %q, want %q", c.in, got, c.want)
			}
			if again := cleanText(got); again != got {
				t.Fatalf("cleanText 不幂等: %q -> %q", got, again)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("输出非法 UTF-8: %q", got)
			}
		})
	}
}

// TestTruncateUTF8 截断不劈开多字节字符：汉字、4 字节 emoji、ASCII 精确截断。
func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		maxBytes int
	}{
		{"ASCII 精确截断", strings.Repeat("a", 200), 120},
		{"汉字边界截断", strings.Repeat("汉", 100), 121}, // 121 落在第 31 个汉字中间
		{"4 字节 emoji 边界截断", strings.Repeat("\U0001F600", 40), 130}, // 130 落在 emoji 中间
		{"超长中文+emoji 混排", strings.Repeat("注入\U0001F4A5", 30), 119},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := truncateUTF8(c.in, c.maxBytes)
			if len(got) > c.maxBytes {
				t.Fatalf("截断后 %d 字节 > 上限 %d", len(got), c.maxBytes)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("截断结果非法 UTF-8（字符被劈开）: %q", got)
			}
		})
	}
	t.Run("空与负上限", func(t *testing.T) {
		if truncateUTF8("abc", 0) != "" || truncateUTF8("abc", -1) != "" {
			t.Fatal("maxBytes<=0 应返回空串")
		}
	})
	t.Run("短串原样返回", func(t *testing.T) {
		if got := truncateUTF8("SQL注入", 120); got != "SQL注入" {
			t.Fatalf("got %q", got)
		}
	})
}

// TestFindingFilenameRuneSafe 中文/emoji 标题超长时按字符边界截断，
// 生成的文件名必须是合法 UTF-8（zip 才会置 UTF-8 标志位，Windows 解名不乱码）。
func TestFindingFilenameRuneSafe(t *testing.T) {
	cases := []struct {
		name  string
		title string
	}{
		{"超长中文标题（>120 字节）", strings.Repeat("命令注入漏洞", 30)},
		{"emoji 标题", "RCE 💥确认\U0001F680" + strings.Repeat("溢出", 40)},
		{"4 字节生僻字符", strings.Repeat("𠀀", 80)}, // U+20000，4 字节/字
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &db.DBFinding{ID: 42, Severity: "critical", Name: c.title}
			name := FindingFilename(f)
			if !strings.HasSuffix(name, ".md") {
				t.Fatalf("缺 .md 后缀: %q", name)
			}
			base := strings.TrimSuffix(name, ".md")
			if len(base) > 120 {
				t.Fatalf("文件名主体 %d 字节超 120 上限", len(base))
			}
			if !utf8.ValidString(name) {
				t.Fatalf("文件名非法 UTF-8: %q", name)
			}
			// 截断不得劈开字符：再次清洗应原样保留（无 U+FFFD 注入）。
			if strings.ContainsRune(name, '\uFFFD') {
				t.Fatalf("文件名含 U+FFFD（截断劈开了字符）: %q", name)
			}
			if strings.ContainsAny(name, "/\\") {
				t.Fatalf("文件名含路径分隔符: %q", name)
			}
		})
	}
	t.Run("短中文名完整保留", func(t *testing.T) {
		f := &db.DBFinding{ID: 7, Severity: "high", Name: "SQL注入"}
		if got := FindingFilename(f); got != "high_SQL注入__7.md" { // `#` 属于被替换字符
			t.Fatalf("got %q", got)
		}
	})
}

// TestAttachmentDisposition RFC 5987：ASCII 名走简单形，中文/emoji 名补
// filename*=UTF-8''，引号反斜杠换 _，空名兜底 download。
func TestAttachmentDisposition(t *testing.T) {
	t.Run("纯 ASCII 简单形", func(t *testing.T) {
		want := `attachment; filename="report-20261118.docx"`
		if got := AttachmentDisposition("report-20261118.docx"); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("中文名带 filename*", func(t *testing.T) {
		got := AttachmentDisposition("渗透测试报告.docx")
		if !strings.HasPrefix(got, `attachment; filename="______.docx"; filename*=UTF-8''`) {
			t.Fatalf("got %q", got)
		}
		star := got[strings.Index(got, "filename*=UTF-8''")+len("filename*=UTF-8''"):]
		if dec, err := url.PathUnescape(star); err != nil || dec != "渗透测试报告.docx" {
			t.Fatalf("filename* 解码不符: %q (err=%v)", star, err)
		}
	})
	t.Run("emoji 名", func(t *testing.T) {
		got := AttachmentDisposition("报告💥.md")
		star := got[strings.Index(got, "filename*=UTF-8''")+len("filename*=UTF-8''"):]
		if dec, err := url.PathUnescape(star); err != nil || dec != "报告💥.md" {
			t.Fatalf("filename* 解码不符: %q (err=%v)", star, err)
		}
	})
	t.Run("引号与反斜杠不破坏头结构", func(t *testing.T) {
		got := AttachmentDisposition(`a"b\c.md`)
		if strings.Count(got, `filename="`) != 1 || !strings.Contains(got, `filename="a_b_c.md"`) {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("空名兜底", func(t *testing.T) {
		if got := AttachmentDisposition(""); got != `attachment; filename="download"` {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("纯非 ASCII 兜底", func(t *testing.T) {
		got := AttachmentDisposition("报告") // 两字符 → ASCII 位是 "__"，仍保留兜底名
		if !strings.HasPrefix(got, `attachment; filename="__"; filename*=UTF-8''`) {
			t.Fatalf("got %q", got)
		}
	})
}
