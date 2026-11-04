package db

import (
	"strings"
	"testing"
)

// cidr 是渗透里最高频的资产查询（「这个网段里有哪些主机」）。之前 DSL 没有它，
// agent 只能试 `ip >= 10.0.0.0`，而 ip 是字符串字段不支持比较运算符——
// 实测 24 次「字符串字段 ip 不支持运算符 >=」+ 11 次语法错误，全是这一个
// 能力缺失逼出来的。
func TestValidateDSLAcceptsCidr(t *testing.T) {
	for _, ok := range []string{
		"cidr=10.10.0.0/16",
		"cidr==192.168.1.0/24",
		"cidr=10.0.0.0/8 AND port==443",
		"cidr=10.0.0.0/8 OR cidr=172.16.0.0/12",
	} {
		if err := ValidateDSL(ok); err != nil {
			t.Errorf("ValidateDSL(%q) 应通过: %v", ok, err)
		}
	}
}

// cidr 的值必须是网段，不能是裸 IP 或乱码。
func TestValidateDSLRejectsBadCidr(t *testing.T) {
	for _, bad := range []string{
		"cidr=10.10.70.17",     // 裸 IP，不是网段
		"cidr=not-a-network",   // 乱码
		"cidr=10.10.0.0/16/24", // 多一段
	} {
		if err := ValidateDSL(bad); err == nil {
			t.Errorf("ValidateDSL(%q) 应报错", bad)
		}
	}
}

// cidr 生成的 SQL 必须用 inet 包含运算（>>=），且对非 IP 的 ip 值安全
// （try_inet 返回 NULL 而不是抛 22P02）。
func TestBuildDSLWhereCidrUsesInetContainment(t *testing.T) {
	node, err := ParseDSL("cidr=10.10.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "try_inet(ip)") || !strings.Contains(where, ">>=") {
		t.Errorf("where=%q 应当用 try_inet(ip) >>= 网段", where)
	}
	if len(args) != 1 || args[0] != "10.10.0.0/16" {
		t.Errorf("args=%v 应当只有一个网段参数", args)
	}
}

// cidr != 的语义：不在网段内的都算（NULL 也算，因为 ip 可能是主机名）。
func TestBuildDSLWhereCidrNotEqual(t *testing.T) {
	node, err := ParseDSL("cidr!=10.10.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	where, _, err := buildDSLWhere(node)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(where, "NOT") {
		t.Errorf("where=%q 应当带 NOT", where)
	}
}
