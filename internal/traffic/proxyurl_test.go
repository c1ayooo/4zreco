package traffic

import "testing"

// 批量导入的入口是 ValidateProxyURL：url.Parse 对「坏行这不是地址」这类不含
// 空格的垃圾串几乎不报错（它当成一个 path），于是乱码会被当成合法代理收进来。
// 这里盯住这条防线。
func TestValidateProxyURLRejectsGarbage(t *testing.T) {
	bad := []string{
		"http://坏行这不是地址",
		"http://has space",
		"not-a-url",
		"ftp://1.2.3.4:21",
		"http://",
		"http://1.2.3.4:abc",
	}
	for _, raw := range bad {
		if _, err := ValidateProxyURL(raw); err == nil {
			t.Errorf("ValidateProxyURL(%q) 应报错", raw)
		}
	}
	good := []string{
		"http://1.2.3.4:8080",
		"https://proxy.example.com:3128",
		"socks5://user:pass@5.6.7.8:1080",
		"http://a:1", // 单标签主机名：内网常见，不能误杀
		"http://[::1]:8080",
	}
	for _, raw := range good {
		if _, err := ValidateProxyURL(raw); err != nil {
			t.Errorf("ValidateProxyURL(%q) 不该报错: %v", raw, err)
		}
	}
}
