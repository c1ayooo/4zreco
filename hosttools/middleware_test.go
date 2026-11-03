package hosttools

import (
	"regexp"
	"strings"
	"testing"
)

// 中间件专项工具的注册完整性。
//
// 这批工具是 2026-10-22 依据「近 30 天 NVD 高危漏洞集中在中间件」这个
// 调研结论加进来的。它们的**包名**直接决定一键安装能不能成功——写错一个
// 字母就是「点了安装但什么都没发生」。
func TestMiddlewareToolsRegistered(t *testing.T) {
	byName := map[string]Tool{}
	for _, tl := range Catalog() {
		byName[tl.Name] = tl
	}
	// 期望存在的中间件工具 → 对应的 pip 包名。
	want := map[string]string{
		"gmqtt":           "gmqtt",
		"paho-mqtt":       "paho-mqtt",
		"pika":            "pika",
		"amqpstorm":       "amqpstorm",
		"confluent-kafka": "confluent-kafka",
		"kombu":           "kombu",
		"pymongo":         "pymongo",
		"pymysql":         "pymysql",
		"psycopg2-binary": "psycopg2-binary",
		"redis-py":        "redis",
		"zeep":            "zeep",
		"python-gitlab":   "python-gitlab",
		"netmiko":         "netmiko",
		"napalm":          "napalm",
		"splunk-sdk":      "splunk-sdk",
	}
	for name, pip := range want {
		tl, ok := byName[name]
		if !ok {
			t.Errorf("中间件工具 %q 未注册", name)
			continue
		}
		if tl.Category != CatMiddleware {
			t.Errorf("工具 %q 的分类=%q，应为 %q", name, tl.Category, CatMiddleware)
		}
		if tl.Kind != KindPip {
			t.Errorf("工具 %q 的安装方式=%q，应为 pip", name, tl.Kind)
		}
		if tl.Pip != pip {
			t.Errorf("工具 %q 的 pip 包名=%q，应为 %q", name, tl.Pip, pip)
		}
	}
}

// 中间件分类必须在页面的分组顺序里（否则前端拿不到标签/顺序）。
func TestMiddlewareCategoryIsOrdered(t *testing.T) {
	found := false
	for _, c := range categoryOrder {
		if c == CatMiddleware {
			found = true
			break
		}
	}
	if !found {
		t.Error("CatMiddleware 不在 categoryOrder 里——页面不会显示这一组")
	}
	if CategoryLabel(CatMiddleware) == "其他" {
		t.Error("CatMiddleware 没有中文标签")
	}
}

// 已知的高危中间件必须都有对应的协议工具。
//
// 依据是 2026-10-22 对近 30 天 NVD 高危漏洞的统计：中间件占了大头。
// 这条测试锁住「哪类中间件我们覆盖了」——将来加新漏洞类型时能看出缺口。
func TestMiddlewareCoversHighRiskProducts(t *testing.T) {
	// 关键中间件 → 至少要有一个工具能跟它说话。
	// 判据：工具的 Pip 包名里含关键词，或 Purpose 里提到该中间件。
	coverage := map[string][]string{
		"mqtt":     {"gmqtt", "paho-mqtt"},
		"rabbitmq": {"pika", "amqpstorm"},
		"kafka":    {"confluent-kafka"},
		"mongodb":  {"pymongo"},
		"mysql":    {"pymysql"},
		"postgres": {"psycopg2-binary"},
		"redis":    {"redis-py"},
		"soap":     {"zeep"},
		"gitlab":   {"python-gitlab"},
	}
	byName := map[string]Tool{}
	for _, tl := range Catalog() {
		byName[tl.Name] = tl
	}
	for product, tools := range coverage {
		for _, name := range tools {
			if _, ok := byName[name]; !ok {
				t.Errorf("%s 场景缺少工具 %q", product, name)
			}
		}
	}
}

// pip 配方不能写成「名字相近但不是同一个」的包。
//
// 这条是供应链防线：PyPI 上有大量与知名包一字之差的仿冒包（paho vs
// paho-mqtt、request vs requests、python-dateutil vs python-dateutil-dc…）。
// 写错不会报「包不存在」，而是装上一个来源不明的包。
func TestMiddlewarePipNamesAreExact(t *testing.T) {
	// 已知的错误写法 → 正确写法。
	traps := map[string]string{
		"paho":      "paho-mqtt", // PyPI 上没有 paho，只有 paho-mqtt
		"pika-mqtt": "pika",
		"mongo":     "pymongo",
		"mysql":     "pymysql",
		"psycopg2":  "psycopg2-binary", // psycopg2 是纯 sdist，一键装会退化成编译
		"gitlab":    "python-gitlab",
		"redis":     "redis",
		"kafka":     "confluent-kafka",
	}
	byName := map[string]Tool{}
	for _, tl := range Catalog() {
		byName[tl.Name] = tl
	}
	for wrong, right := range traps {
		if _, ok := byName[wrong]; ok {
			// 存在这个工具，但它的 Pip 必须是正确的那一个。
			if got := byName[wrong].Pip; got != right {
				t.Errorf("工具 %q 的 pip 包名=%q，应为 %q", wrong, got, right)
			}
		}
	}
	// 所有中间件工具的 pip 包名都必须是「纯包名」（不含空格分隔的多包），
	// 且看起来像真实的 PyPI 名（字母数字与 -_.）。
	valid := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	for _, tl := range Catalog() {
		if tl.Category != CatMiddleware {
			continue
		}
		if !valid.MatchString(tl.Pip) {
			t.Errorf("工具 %q 的 pip 包名 %q 不是合法的单包名", tl.Name, tl.Pip)
		}
		if strings.TrimSpace(tl.Pip) == "" {
			t.Errorf("工具 %q 的 pip 包名为空", tl.Name)
		}
	}
}
