package vulnintel

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// cveRowLite 是等价性测试用的最小 CVE 行（只需 CVEID 与 Product）。
type cveRowLite struct {
	CVEID   string
	Product string
}

// matchLegacy 是重构前的匹配算法：O(资产 × tech × product) 三重嵌套。
// 保留它作为「参照实现」——新算法必须与它给出同样的命中集合。
func matchLegacy(assets [][]string, cves []cveRowLite) map[int][]string {
	byProduct := map[string][]cveRowLite{}
	for _, c := range cves {
		byProduct[c.Product] = append(byProduct[c.Product], c)
	}
	out := map[int][]string{}
	for i, techs := range assets {
		var hit []cveRowLite
		for _, tech := range techs {
			toks := techTokens(tech)
			if len(toks) == 0 {
				continue
			}
			for product, cs := range byProduct {
				pts := cpeTokens(product)
				for _, pt := range pts {
					for _, tok := range toks {
						if tok == pt {
							hit = append(hit, cs...)
							break
						}
					}
				}
			}
		}
		for _, c := range hit {
			out[i] = append(out[i], c.CVEID)
		}
	}
	return out
}

// matchIndexed 是重构后的算法：token 倒排索引。
func matchIndexed(assets [][]string, cves []cveRowLite) map[int][]string {
	tokIndex := map[string][]cveRowLite{}
	for _, c := range cves {
		for _, pt := range cpeTokens(c.Product) {
			tokIndex[pt] = append(tokIndex[pt], c)
		}
	}
	out := map[int][]string{}
	for i, techs := range assets {
		var hit []cveRowLite
		seen := map[string]bool{}
		for _, tech := range techs {
			for _, tok := range techTokens(tech) {
				for _, c := range tokIndex[tok] {
					if seen[c.CVEID] {
						continue
					}
					seen[c.CVEID] = true
					hit = append(hit, c)
				}
			}
		}
		for _, c := range hit {
			out[i] = append(out[i], c.CVEID)
		}
	}
	return out
}

func normHits(m map[int][]string) map[int][]string {
	out := map[int][]string{}
	for k, v := range m {
		s := append([]string{}, v...)
		sort.Strings(s)
		// 去重：旧实现可能对同一 CVE 重复 append（同一 product 被多个 token 命中）
		dedup := s[:0]
		for i, x := range s {
			if i == 0 || x != s[i-1] {
				dedup = append(dedup, x)
			}
		}
		out[k] = dedup
	}
	return out
}

// 重构（倒排索引）不能改变匹配结果。用随机数据 + 真实词表跑等价性断言。
func TestIndexedMatchEqualsLegacy(t *testing.T) {
	techs := []string{
		"Apache httpd 2.4.49", "nginx", "OpenSSH", "MySQL 5.7",
		"Microsoft Windows Server 2008 R2", "Huawei AirEngine",
		"PostgreSQL 14", "redis", "Tomcat", "httpd", "http_server",
		"IIS", "VMware ESXi", "unknown-thing", "",
	}
	products := []string{
		"http_server", "apache_tomcat", "nginx", "openssh", "mysql",
		"microsoft_windows_server_2008", "ubuntu_linux", "windows_server_2008",
		"tomcat", "postgresql", "redis", "vmware_esxi", "office_excel_viewer",
		"openview_network_node_manager", "acrobat",
	}

	rng := rand.New(rand.NewSource(20261020))
	for round := 0; round < 40; round++ {
		nAsset := 1 + rng.Intn(6)
		nCVE := 1 + rng.Intn(8)
		var assets [][]string
		for i := 0; i < nAsset; i++ {
			var ts []string
			for j := 0; j < 1+rng.Intn(3); j++ {
				ts = append(ts, techs[rng.Intn(len(techs))])
			}
			assets = append(assets, ts)
		}
		var cves []cveRowLite
		for i := 0; i < nCVE; i++ {
			cves = append(cves, cveRowLite{
				CVEID:   fmt.Sprintf("CVE-2024-%05d", i),
				Product: products[rng.Intn(len(products))],
			})
		}
		got := normHits(matchIndexed(assets, cves))
		want := normHits(matchLegacy(assets, cves))
		if len(got) != len(want) {
			t.Fatalf("round %d: 命中资产数不同 got=%d want=%d", round, len(got), len(want))
		}
		for k, wv := range want {
			gv, ok := got[k]
			if !ok {
				t.Fatalf("round %d: 资产 %d 旧算法命中 %v，新算法没命中", round, k, wv)
			}
			if len(gv) != len(wv) {
				t.Fatalf("round %d: 资产 %d 命中数不同 got=%v want=%v", round, k, gv, wv)
			}
			for i := range wv {
				if gv[i] != wv[i] {
					t.Fatalf("round %d: 资产 %d 命中集合不同 got=%v want=%v", round, k, gv, wv)
				}
			}
		}
	}
}

// 倒排索引必须正确处理「一个 product 多个 cpeToken」的重复命中：
// 同一 CVE 通过多个 token 命中同一资产时，只应出现一次。
func TestIndexedMatchDedupsWithinAsset(t *testing.T) {
	// "http_server" 的 cpeTokens 含 http_server / httserver / httpd 等多个形态，
	// techTokens("http_server") 也会产出多个形态 → 必然多路命中同一个 CVE。
	assets := [][]string{{"http_server"}}
	cves := []cveRowLite{{CVEID: "CVE-2024-00001", Product: "http_server"}}
	got := matchIndexed(assets, cves)
	if ids := got[0]; len(ids) != 1 {
		t.Fatalf("同一 CVE 应只出现一次，实际 %v", ids)
	}
}

// 跨资产不能互相去重：两个资产命中同一个 CVE 是两件事。
func TestIndexedMatchKeepsSameCVEAcrossAssets(t *testing.T) {
	assets := [][]string{{"nginx"}, {"nginx"}}
	cves := []cveRowLite{{CVEID: "CVE-2024-00001", Product: "nginx"}}
	got := matchIndexed(assets, cves)
	if len(got) != 2 {
		t.Fatalf("两个资产都应命中，实际命中 %d 个资产", len(got))
	}
	for k, ids := range got {
		if len(ids) != 1 || ids[0] != "CVE-2024-00001" {
			t.Fatalf("资产 %d 命中异常: %v", k, ids)
		}
	}
}
