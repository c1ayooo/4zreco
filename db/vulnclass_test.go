package db

import "testing"

func TestNormalizeVulnClass(t *testing.T) {
	cases := []struct{ in, want string }{
		// 别名表:中英变体都折到标准类别
		{"SQLi", "注入"}, {"sql_injection", "注入"}, {"SQL注入", "注入"},
		{"idor", "未授权访问"}, {"IDOR", "未授权访问"}, {"水平越权", "未授权访问"},
		{"WeakPassword", "弱口令"}, {"默认凭据", "弱口令"},
		{"path traversal", "任意文件读取"}, {"LFI", "任意文件读取"},
		{"RCE", "RCE"}, {"远程代码执行", "RCE"}, {"cmd_injection", "注入"},
		{"SSRF", "SSRF"}, {"永恒之蓝", "已知漏洞"}, {"CVE-2017-0144", "已知漏洞"},
		// 大小写/空白/分隔符不敏感
		{"XSS", "XSS"}, {" xss ", "XSS"},
		// 白名单成员原样(标准写法回自己)
		{"注入", "注入"}, {"未授权访问", "未授权访问"}, {"其他", "其他"},
		// 未命中:TrimSpace 原值保留(不销毁信息)
		{"永恒蓝屏", "永恒蓝屏"}, {"自定义类别", "自定义类别"},
		// 空
		{"", ""}, {"  ", ""},
	}
	for _, c := range cases {
		if got := NormalizeVulnClass(c.in); got != c.want {
			t.Errorf("NormalizeVulnClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
