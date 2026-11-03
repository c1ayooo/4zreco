package db

import (
	"strings"
	"testing"
)

// 空值查询：agent 要能查出「端口开着但服务未识别」的资产。
//
// 背景：实测任务里 2380 个 service 资产有 2073 个 service_name 为空
//（扫了端口但没做服务识别），而这些正是下一步该挖的面。agent 必须能
// 看见它们——但 `service_name=` 是模糊匹配（ILIKE '%%' 匹配所有非空值），
// `service_name==""` 才是精确匹配空串。
func TestDSLEmptyValueQuery(t *testing.T) {
	node, err := ParseDSL(`service_name==""`)
	if err != nil {
		t.Fatalf("service_name==\"\" 应能解析: %v", err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatalf("构建 where 失败: %v", err)
	}
	if !strings.Contains(where, "service_name") {
		t.Errorf("where 应含 service_name: %s", where)
	}
	// 空值必须同时匹配 NULL 与空串：资产库里大量 HTTP 服务的 service_name
	// 存的是 NULL（实测 2180 个里 2073 个），只匹配 '' 等于什么都查不到。
	if !strings.Contains(where, "IS NULL") {
		t.Errorf("空值查询应覆盖 NULL: %s", where)
	}
	if !strings.Contains(where, "= ''") {
		t.Errorf("空值查询应覆盖空串: %s", where)
	}
	if len(args) != 0 {
		t.Errorf("空值查询不需要参数,得到 %v", args)
	}
}

// 非空值的 == 语义不变（精确等值，不带 ILIKE）。
func TestDSLEmptyValueDoesNotAffectNonEmpty(t *testing.T) {
	node, err := ParseDSL(`service_name==mysql`)
	if err != nil {
		t.Fatal(err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(where, "IS NULL") {
		t.Errorf("非空值不应带 NULL 判定: %s", where)
	}
	if !strings.Contains(where, "= $1") {
		t.Errorf("应为精确等值: %s", where)
	}
	if len(args) != 1 || args[0] != "mysql" {
		t.Errorf("参数应为 mysql,得到 %v", args)
	}
}

// 反过来：service_name= 不能用来查空值（它是模糊匹配，会匹配所有非空值）。
// 这条断言是为了把语义钉死，防止以后有人把 = 也改成精确匹配。
func TestDSLFuzzyEmptyValueDoesNotMatchEmpty(t *testing.T) {
	node, err := ParseDSL(`service_name=`)
	if err == nil {
		where, _, _ := buildDSLWhere(node)
		if !strings.Contains(where, "ILIKE") {
			t.Errorf("= 语义应是模糊匹配(ILIKE): %s", where)
		}
	}
}
