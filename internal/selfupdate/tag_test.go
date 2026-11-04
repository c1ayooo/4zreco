package selfupdate

import "testing"

// 版本号两种写法（带/不带 v）必须能互相转换——Release tag 是 v0.3.23，
// 而二进制里注入的版本号是 0.3.23，助手按后者去查会 404。
func TestAlternateTag(t *testing.T) {
	cases := map[string]string{
		"v0.3.23": "0.3.23",
		"0.3.23":  "v0.3.23",
		"v1.0.0":  "1.0.0",
		"1.0.0":   "v1.0.0",
	}
	for in, want := range cases {
		if got := alternateTag(in); got != want {
			t.Errorf("alternateTag(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// ValidVersionTag 是 hostd /self-upgrade 的唯一入参校验，必须挡掉花活。
func TestValidVersionTag(t *testing.T) {
	ok := []string{"0.3.23", "v0.3.23", "1.0.0"}
	for _, s := range ok {
		if !ValidVersionTag(s) {
			t.Errorf("%q 应被接受", s)
		}
	}
	bad := []string{"", "latest", "0.3", "0.3.23.4", "../etc/passwd", "0.3.23;id", "v0.3.23\n"}
	for _, s := range bad {
		if ValidVersionTag(s) {
			t.Errorf("%q 应被拒绝", s)
		}
	}
}
