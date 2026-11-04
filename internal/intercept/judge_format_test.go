package intercept

import "testing"

// 裁决回复的排版偏差（半角冒号、换行、半角分号）不该被判成「无法解析」——
// 开启思考的模型尤其容易多几个换行。原先一律判失败、直接走失败策略，
// 于是每次裁决都掉进兜底。
func TestParseVerdictToleratesFormatting(t *testing.T) {
	cases := []struct {
		name  string
		reply string
	}{
		{"标准", `{"decision":"allow","comment":"实际操作：读取文件；成功后的后果：返回内容；命中规则：A5"}`},
		{"半角冒号", `{"decision":"allow","comment":"实际操作:读取文件;成功后的后果:返回内容;命中规则:A5"}`},
		{"带换行", `{"decision":"deny","comment":"实际操作：删除订单\n成功后的后果：记录丢失\n命中规则：D4"}`},
		{"代码围栏", "```json\n" + `{"decision":"ask","comment":"实际操作：删文件；成功后的后果：丢失；命中规则：ASK"}` + "\n```"},
		{"多带字段", `{"decision":"allow","comment":"实际操作：读取文件；成功后的后果：返回内容；命中规则：A5","reason":"只读操作"}`},
		{"三段无标签", `{"decision":"allow","comment":"读取文件；返回内容；命中规则 A5"}`},
	}
	for _, c := range cases {
		v := ParseVerdict(c.reply)
		if v.Action == "" {
			t.Errorf("%s: 解析失败，应容忍排版偏差", c.name)
			continue
		}
		if v.Reason == "" {
			t.Errorf("%s: reason 为空", c.name)
		}
	}
}

// 三段缺一段仍然必须判无效——容错只动排版，不补语义。
func TestParseVerdictStillRejectsIncomplete(t *testing.T) {
	bad := []string{
		`{"decision":"allow","comment":"读取文件"}`,
		`{"decision":"allow","comment":"实际操作：读取文件；成功后的后果：返回内容"}`,
		`{"decision":"allow","comment":"实际操作：；成功后的后果：返回内容；命中规则：A5"}`,
		`{"decision":"maybe","comment":"实际操作：读取文件；成功后的后果：返回内容；命中规则：A5"}`,
		`{"decision":"allow"}`,
		`not json at all`,
	}
	for _, b := range bad {
		if v := ParseVerdict(b); v.Action != "" {
			t.Errorf("ParseVerdict(%q) 应判无效，得到 action=%q", b, v.Action)
		}
	}
}

// 失败/超时的默认策略按「人不在电脑前」定：裁决失败转人工、人工超时放行。
// 断言这些默认值——它们一旦被改回去，人不在时就会卡死或静默失效。
func TestJudgeDefaultsAreHumanAbsentFriendly(t *testing.T) {
	if defaultJudgeTimeoutSecs < 60 {
		t.Errorf("裁决超时 %ds 太短：带思考的模型来不及", defaultJudgeTimeoutSecs)
	}
	if defaultJudgeFailAction != "ask" {
		t.Errorf("裁决失败策略=%q，应为 ask（模型挂了不能静默放行）", defaultJudgeFailAction)
	}
	if defaultJudgeAskTimeoutAction != "allow" {
		t.Errorf("人工审批超时策略=%q，应为 allow（人不在时不卡死）", defaultJudgeAskTimeoutAction)
	}
	if defaultJudgeAskTimeoutSecs < 120 {
		t.Errorf("人工审批超时 %ds 太短，操作员来不及回来看", defaultJudgeAskTimeoutSecs)
	}
}
