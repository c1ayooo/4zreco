package llmguard

import "testing"

// 判定正则边界：明确拒绝要抓到，正常否认/技术表述不能误判（对照上游测试意图重写）。
func TestClassifyRefusalBoundaries(t *testing.T) {
	cases := []struct {
		name string
		text string
		want RefusalKind
	}{
		// —— 明确拒绝（要抓到）——
		{"英文sorry开头", "I'm sorry, but I can't help with that.", RefusalExplicit},
		{"英文cannot assist", "I cannot assist with this request.", RefusalExplicit},
		{"英文as an AI", "As an AI, I won't fulfill this request.", RefusalExplicit},
		{"英文unable", "I am unable to help with hacking.", RefusalExplicit},
		{"中文抱歉+不能协助", "抱歉，我不能协助完成这个请求。", RefusalExplicit},
		{"中文很抱歉+无法提供", "很抱歉，我无法提供这类内容。", RefusalExplicit},
		{"中文我不能帮助开头", "我不能帮助进行端口扫描。", RefusalExplicit},
		{"作为AI开头", "作为一个AI语言模型，我不能协助该操作。", RefusalExplicit},
		{"我理解你的担忧", "我理解你的担忧，但是我不能协助这个请求。", RefusalExplicit},
		{"客套两句再拒绝", "好的。不过，我无法帮助完成这个任务。", RefusalExplicit},
		{"unfortunately开头", "Unfortunately, I can't comply with this.", RefusalExplicit},

		// —— 条件式拒绝（单独分类，不硬拒）——
		{"英文if you have authorization", "I can't help unless you have authorization to test this system.", RefusalConditional},
		{"英文authorized testing only", "I can't provide payloads — this is authorized penetration testing only.", RefusalConditional},
		{"中文如果有授权前提", "我不能协助，如果你有授权的前提下可以再谈。", RefusalConditional},
		{"中文需要授权文件", "我无法提供帮助，需要您提供授权证明。", RefusalConditional},
		{"中文仅限授权用途", "这类请求我无法处理，仅限授权用途。", RefusalConditional},

		// —— 正常否认/技术表述（不能误判）——
		{"空串", "", RefusalNone},
		{"纯技术回答", "目标 80 端口开放，运行 nginx 1.24。", RefusalNone},
		{"否认对方说法", "我不能否认这个漏洞存在，证据已经列出来了。", RefusalNone},
		{"无法确定是正常表述", "仅凭 banner 无法确定具体版本，需要进一步指纹验证。", RefusalNone},
		{"正常的技术讨论", "我会帮助你分析这个 SQL 注入点的可利用性。", RefusalNone},
		{"授权后才能访问是技术描述", "该接口需要授权后才能访问，未登录返回 401。", RefusalNone},
		{"英文正常开头", "Here's the nmap result for the target.", RefusalNone},
		{"英文403描述", "The server denied the request with 403; the login page is at /admin.", RefusalNone},
		{"中文开头但只是计划", "好的，我先从子域名枚举开始，然后对开放端口做指纹识别。", RefusalNone},
	}
	for _, c := range cases {
		if got := ClassifyRefusal(c.text); got != c.want {
			t.Errorf("%s: ClassifyRefusal(%q) = %v, want %v", c.name, c.text, got, c.want)
		}
	}
}

func TestLooksLikeRefusal(t *testing.T) {
	if !LooksLikeRefusal("I'm sorry, I can't help with that.") {
		t.Error("明确拒绝应判为疑似拒答")
	}
	if LooksLikeRefusal("扫描完成，发现 3 个开放端口。") {
		t.Error("正常产出不应判为拒答")
	}
}

// Hint 分段：第 1 次重试给授权说明，之后给继续输出说明。
func TestHintAttempts(t *testing.T) {
	if Hint(1) != AuthorizedHint {
		t.Error("attempt=1 应返回 AuthorizedHint")
	}
	if Hint(2) != ContinueHint || Hint(3) != ContinueHint {
		t.Error("attempt>=2 应返回 ContinueHint")
	}
}

// HasAuthorizationContext：只有带平台注入授权口径的 system 才放行自动重试。
func TestHasAuthorizationContext(t *testing.T) {
	auth := []string{"你是……", "【任务口径（代码内置）】本任务是第一方授权安全验证……"}
	if !HasAuthorizationContext(auth) {
		t.Error("带授权口径的 system 应返回 true")
	}
	if HasAuthorizationContext([]string{"你是一个通用助手，可以谈论授权相关话题。"}) {
		t.Error("泛化提到「授权」的普通助手不应放行")
	}
	if HasAuthorizationContext(nil) {
		t.Error("空 system 不应放行")
	}
}
