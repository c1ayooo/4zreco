package chains

import (
	"strings"
	"testing"
)

func TestDisciplineCoversCoreRules(t *testing.T) {
	d := Discipline()
	for _, want := range []string{"回显阴性", "版本 ≠ 漏洞", "异常 ≠ 漏洞", "蜜罐", "证据不足不登记", "反问纪律（chains L2）"} {
		if !strings.Contains(d, want) {
			t.Errorf("Discipline 缺关键纪律 %q", want)
		}
	}
}

func TestSkeletonDispatch(t *testing.T) {
	cases := map[string]string{
		"对 id 参数做 SQL 注入探测":       "【SQLi 反问链】",
		"验证搜索框反射型 XSS":            "【XSS 反问链】",
		"命令执行漏洞验证":                "【RCE 反问链】",
		"测试 /download?file= 路径遍历": "【文件操作 反问链】",
		"验证图片代理 SSRF":             "【SSRF 反问链】",
		"测越权 /api/user/1":         "【认证/越权 反问链】",
		"子域枚举与指纹识别":               "【信息收集 反问链】",
		"fastjson 反序列化":           "【反序列化 反问链】",
		"头像上传接口测试":                "【文件上传 反问链】",
		// 上游路由里「注入」优先命中 SQLi，故 XXE 用例不能带「注入」二字
		"XML 外部实体 xxe 读文件": "【XXE 反问链】",
		"随便看看这个页面":         "【通用反问链】",
	}
	for intent, want := range cases {
		if got := Skeleton(intent, ""); !strings.Contains(got, want) {
			t.Errorf("Skeleton(%q) 应命中 %s，实际 %q", intent, want, firstLine(got))
		}
	}
}

// 大小写不敏感：路由在内部统一 ToLower。
func TestSkeletonCaseInsensitive(t *testing.T) {
	if got := Skeleton("SQLi in /api/login", ""); !strings.Contains(got, "【SQLi 反问链】") {
		t.Errorf("大写 SQLi 未命中：%q", firstLine(got))
	}
	if got := Skeleton("", "SSRF"); !strings.Contains(got, "【SSRF 反问链】") {
		t.Errorf("vulnclass 参数未参与路由：%q", firstLine(got))
	}
}

// 空意图兜底到通用链，不返回空串（否则注入等于没注入）。
func TestSkeletonEmptyFallback(t *testing.T) {
	got := Skeleton("", "")
	if strings.TrimSpace(got) == "" {
		t.Fatal("空意图应返回通用骨架而不是空串")
	}
	if !strings.Contains(got, "【通用反问链】") {
		t.Errorf("空意图应命中通用链，实际 %q", firstLine(got))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
