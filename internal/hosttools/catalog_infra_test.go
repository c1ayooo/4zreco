package hosttools

import (
	"strings"
	"testing"
)

// 上游（Pojun 0.4.31-0.4.81 缺口段）扩容的 24 个工具必须都在目录里——
// 这批工具覆盖移动端逆向 / AD 进阶 / 利用 / 云原生 / 侦察五条线，
// 漏一个就是对应攻击面在体检页和提示词注入里整体缺席。
func TestCatalogCoversUpstreamExpansion(t *testing.T) {
	want := []string{
		"aapt", "adb", "adidnsdump", "apktool", "arjun", "awscli",
		"bloodhound-python", "certipy", "frida", "gau", "jadx", "java",
		"jwt_tool", "kerbrute", "kube-hunter", "kubectl", "ldapdomaindump",
		"objection", "searchsploit", "trivy", "waybackurls", "winpeas",
		"ysoserial", "ysoserial.net",
	}
	// 名字或探测名（ID=Bin）任一命中即可：awscli 的 ID 是 "aws"（Bin 覆盖）。
	byID := map[string]bool{}
	for _, tool := range Catalog() {
		byID[tool.Name] = true
		byID[tool.ID] = true
	}
	for _, id := range want {
		if !byID[id] {
			t.Errorf("上游扩容工具 %s 不在目录里", id)
		}
	}
	// 上游 0.4.69 前后目录是 66→90 项；4zreco 额外保留 chainreactors 三件套
	// （gogo/spray/zombie，上游没有），所以基线是 90+3=93。
	if n := len(catalog); n < 93 {
		t.Errorf("目录不应少于 93 项(上游 90 + chainreactors 三件套),得到 %d", n)
	}
}

// 每个 script 类配方都必须真的带脚本——空脚本的 KindScript 点了安装只会
// 静默跑一个空 /bin/sh，用户看到「安装完成」但什么都没装。
func TestScriptRecipesAreComplete(t *testing.T) {
	for _, tool := range Catalog() {
		if tool.Kind != KindScript {
			continue
		}
		if strings.TrimSpace(tool.Script) == "" {
			t.Errorf("%s 是 KindScript 但 Script 为空", tool.Name)
		}
	}
}

// Detect 表达式必须在生成期就合法：前缀只认 path:/dir:/python:，any: 的每个
// 候选也都要合法——写错的 Detect 会让 detectOne 永远返回 false，工具明明装了
// 体检页却显示缺失。
func TestDetectExpressionsAreWellFormed(t *testing.T) {
	for _, tool := range Catalog() {
		if tool.Detect == "" {
			continue
		}
		checkOne := func(d string) {
			kind, target, ok := strings.Cut(d, ":")
			if !ok || target == "" {
				t.Errorf("%s 的探测表达式 %q 缺前缀或目标", tool.Name, d)
				return
			}
			switch kind {
			case "path", "dir", "python":
			default:
				t.Errorf("%s 的探测表达式 %q 用了未知前缀 %q", tool.Name, d, kind)
			}
		}
		if rest, ok := strings.CutPrefix(tool.Detect, "any:"); ok {
			for _, cand := range strings.Split(rest, ",") {
				if cand = strings.TrimSpace(cand); cand != "" {
					checkOne(cand)
				}
			}
			continue
		}
		checkOne(tool.Detect)
	}
}

// 依赖新基础设施字段的代表条目：字段拼错的后果是「一键安装」下载 404 或
// 把裸二进制当归档解压。
func TestInfraFieldSemantics(t *testing.T) {
	kerbrute, ok := Lookup("kerbrute")
	if !ok {
		t.Fatal("kerbrute 不在目录里")
	}
	if !kerbrute.Raw {
		t.Error("kerbrute 资产是裸二进制,应标 Raw")
	}
	ys, ok := Lookup("ysoserial")
	if !ok {
		t.Fatal("ysoserial 不在目录里")
	}
	if !ys.Raw || ys.DestPath == "" || ys.Detect == "" {
		t.Error("ysoserial 应同时具备 Raw（裸 jar）/DestPath（装 /opt）/Detect（按目标文件探测）")
	}
	trivy, ok := Lookup("trivy")
	if !ok {
		t.Fatal("trivy 不在目录里")
	}
	if !strings.Contains(trivy.AssetTmpl, "{arch5}") {
		t.Errorf("trivy 资产模板应使用 {arch5}（Linux-64bit 命名）,得到 %q", trivy.AssetTmpl)
	}
	ferox, ok := Lookup("feroxbuster")
	if !ok {
		t.Fatal("feroxbuster 不在目录里")
	}
	if !strings.Contains(ferox.AssetTmpl, "||") {
		t.Errorf("feroxbuster 资产模板应带多候选（||）,得到 %q", ferox.AssetTmpl)
	}
	for _, id := range []string{"java", "apktool", "aapt", "adb", "frida", "objection"} {
		tool, ok := Lookup(id)
		if !ok {
			t.Errorf("%s 不在目录里", id)
			continue
		}
		if tool.Category != CatMobile {
			t.Errorf("%s 应归 CatMobile,得到 %q", id, tool.Category)
		}
	}
}
