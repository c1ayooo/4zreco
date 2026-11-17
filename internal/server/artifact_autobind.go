package server

// 智能关联（移植自上游 v0.4.42）：任务级数据/日志证据自动归属到漏洞。
//
// 数据证据常见「worker 存证据时漏洞还没报出来，事后没人补挂」。这里按
// 「主机交叉」自动补挂：从证据的 name/note/source_url/storage 里提取域名，
// 与漏洞锚定资产的域名/url 求交集——
//   - 命中恰好 1 个漏洞 → 自动绑定（可手动在证据卡里改回任务级）；
//   - 命中多个 → 跳过（歧义，宁可不动）；
//   - 零命中 → 跳过。
// 全程只写 finding_id，不改内容。

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreco/internal/db"
)

var hostInTextRe = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::\d+)?`)

func extractHosts(text string) map[string]bool {
	out := map[string]bool{}
	for _, m := range hostInTextRe.FindAllStringSubmatch(text, 24) {
		h := strings.ToLower(m[1])
		if h != "" && strings.Contains(h, ".") {
			out[h] = true
		}
	}
	return out
}

func (s *Server) autoBindArtifacts(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 500, "PG 不可用")
		return
	}
	arts, err := pg.ListTaskArtifacts(t.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	findings, err := pg.ListFindingsForExport(db.FindingFilter{TaskID: t.ID}, nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	// 漏洞 → 主机集合（证据文本里的主机 + 锚定资产的可读名）
	findingHosts := map[int64]map[string]bool{}
	findingInfo := map[int64]string{}
	assetNames := s.reportAssetNames(findings)
	for _, f := range findings {
		if f.ID == 0 {
			continue
		}
		hosts := map[string]bool{}
		text := f.Name + "\n" + f.Summary + "\n" + f.Evidence
		for h := range extractHosts(text) {
			hosts[h] = true
		}
		for _, aid := range f.AssetIDs {
			for h := range extractHosts(assetNames[aid]) {
				hosts[h] = true
			}
		}
		findingHosts[f.ID] = hosts
		findingInfo[f.ID] = f.Name
		if findingInfo[f.ID] == "" {
			findingInfo[f.ID] = f.VulnClass
		}
	}

	bound := 0
	skipped := 0
	details := []string{}
	for _, a := range arts {
		if a.FindingID != 0 || (a.Kind != "data" && a.Kind != "log") {
			continue
		}
		text := a.Name + "\n" + a.Note + "\n" + a.SourceURL + "\n" + a.Storage
		hosts := extractHosts(text)
		if len(hosts) == 0 {
			skipped++
			continue
		}
		matches := []int64{}
		for fid, fhosts := range findingHosts {
			for h := range hosts {
				if fhosts[h] {
					matches = append(matches, fid)
					break
				}
			}
		}
		if len(matches) != 1 {
			skipped++
			continue
		}
		fid := matches[0]
		if _, err := pg.UpdateTaskArtifactFinding(a.ID, fid); err != nil {
			skipped++
			continue
		}
		bound++
		details = append(details, fmt.Sprintf("%s → #%d %s", a.Name, fid, truncateRunes(findingInfo[fid], 40)))
	}
	sort.Strings(details)
	writeJSON(w, 200, map[string]any{"bound": bound, "skipped": skipped, "details": details})
}

func truncateRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
