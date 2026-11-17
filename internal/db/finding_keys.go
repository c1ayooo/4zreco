package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 多键去重（移植自上游 v0.4.79 db/finding_keys.go）：一条 finding 可以携带多个
// 身份键，强键自动合并、弱键只做候选。
//
// 设计取舍：
//   - root/cve/legacy 是强键，命中即认为同一底层漏洞；
//   - asset_class/name/endpoint/param 是弱键（rank 99），只用于「可能重复」提示
//     （merge_candidates / finding_cases 候选打分），绝不自动合并——endpoint/param
//     描述的是「在哪儿」，同一 host+path 天然可以承载 IDOR、认证绕过、注入、SSRF
//     等多个互不相同的漏洞，把它们当强键等于断言「同一位置就是同一漏洞」；
//   - 所有键都限定同任务。跨任务只在提示里出现，不自动改写。

const (
	FindingKeyRoot       = "root"
	FindingKeyCVE        = "cve"
	FindingKeyEndpoint   = "endpoint"
	FindingKeyParam      = "param"
	FindingKeyLegacy     = "legacy"
	FindingKeyAssetClass = "asset_class"
	FindingKeyName       = "name"
)

type FindingKey struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
}

// strongFindingKeyRank 返回身份键的强度排名：数值越小越强，99 表示弱键。
//
// 身份必须来自语义，位置不能当身份。endpoint / param 仍会生成（供重复提示与
// finding_cases 候选打分），但只算弱键，不参与 RecordFindingTx 自动合并。
func strongFindingKeyRank(kind string) int {
	switch kind {
	case FindingKeyRoot:
		return 1
	case FindingKeyCVE:
		return 2
	case FindingKeyLegacy:
		return 5
	}
	return 99
}

func normalizeRootCauseKey(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == ':', r == '_', r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 96 {
		out = out[:96]
	}
	// 过短或只是通用词的不构成根因标识：它们会把无关漏洞并到一起。
	// 根因键是「显式声明同一根因」的手段，宁缺毋滥——传了无效值等于没传。
	if len(out) < 4 || genericRootCauseKeys[out] {
		return ""
	}
	return out
}

// genericRootCauseKeys 是会被大量互不相同漏洞共用的通用词，不能充当根因标识。
var genericRootCauseKeys = map[string]bool{
	"vuln": true, "vulns": true, "vulnerability": true, "bug": true, "issue": true,
	"xss": true, "sqli": true, "ssrf": true, "idor": true, "rce": true, "csrf": true,
	"injection": true, "inject": true, "auth": true, "authn": true, "authz": true,
	"auth-bypass": true, "info-leak": true, "infoleak": true, "info-disclosure": true,
	"generic": true, "default": true, "unknown": true, "other": true, "misc": true,
	"none": true, "null": true, "test": true, "tmp": true, "todo": true,
}

// normalizeFindingEndpoint 把 URL 或路径归一到 host+path（小写 host、去 query/hash、
// 去尾斜杠）。路径保持大小写——HTTP 路径可能大小写敏感。
func normalizeFindingEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			// fail-closed：无法解析的「URL」不构成身份。此前这里会回退成原文
			// 小写，于是被标点连带的片段（如「http://host（说明文字」）会成为
			// 垃圾键，让分组结果随文案措辞漂移。
			return ""
		}
		host := strings.ToLower(u.Host)
		path := strings.TrimRight(u.EscapedPath(), "/")
		if path == "" {
			path = "/"
		}
		return host + path
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "/")
	if s == "" {
		s = "/"
	}
	return strings.ToLower(s)
}

// findingEndpointIsRoot 判断归一化后的端点是否只是资产基址（没有具体路径）。
// normalizeFindingEndpoint 会去掉非根路径的尾斜杠，因此只有根路径以 "/" 结尾。
func findingEndpointIsRoot(endpoint string) bool {
	return strings.HasSuffix(endpoint, "/")
}

// findingCVERe / findingURLRe 从名称/摘要/证据里提取 CVE 与 http(s) URL。
// 排除字符同时覆盖半角与全角标点：全角左括号不排除会把
// 「http://host（说明文字」整段吞进 URL，产生垃圾键。
var (
	findingCVERe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	findingURLRe = regexp.MustCompile(`(?i)https?://[^\s"'<>（）()【】\[\]，,。；;]+`)
)

// normalizeFindingName 归一漏洞名（剥掉「（完整证据）」这类换皮后缀再压缩空白）。
// 显示名保持原样，只有身份键用归一后的名称。
func normalizeFindingName(name string) string {
	s := findingNameBrackets.ReplaceAllString(name, " ")
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

var findingNameBrackets = regexp.MustCompile(`[（(【\[][^）)】\]]*[）)】\]]`)

// firstFindingURL 从名称/摘要/证据里取第一个 http(s) URL，作为端点键来源。
func firstFindingURL(in RecordFindingInput) string {
	for _, text := range []string{in.Endpoint, in.Name, in.Summary, in.Evidence} {
		if m := findingURLRe.FindString(text); m != "" {
			return m
		}
	}
	if strings.TrimSpace(in.Endpoint) != "" {
		return in.Endpoint
	}
	return ""
}

// FindingDedupKeys 生成本次上报的全部身份键（已去重）。
func FindingDedupKeys(in RecordFindingInput, fp string) []FindingKey {
	seen := map[string]bool{}
	out := make([]FindingKey, 0, 8)
	add := func(kind, key string) {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, FindingKey{Key: key, Kind: kind})
	}

	if root := normalizeRootCauseKey(in.RootCauseKey); root != "" {
		add(FindingKeyRoot, "root:"+root)
	}
	text := in.Name + "\n" + in.Summary + "\n" + in.Evidence
	for _, cve := range findingCVERe.FindAllString(text, -1) {
		add(FindingKeyCVE, "cve:"+strings.ToUpper(cve))
	}
	// 端点键只在路径非根时生成：裸资产基址（host + "/"）不构成端点身份，
	// 否则同一资产上的所有漏洞都会落到同一个 endpoint:<host>/ 键上。
	endpoint := normalizeFindingEndpoint(firstFindingURL(in))
	if endpoint != "" && !findingEndpointIsRoot(endpoint) {
		add(FindingKeyEndpoint, "endpoint:"+endpoint)
		if param := strings.ToLower(strings.TrimSpace(in.Parameter)); param != "" {
			add(FindingKeyParam, "param:"+endpoint+":"+param)
		}
	}
	if fp != "" {
		add(FindingKeyLegacy, "legacy:"+fp)
	}
	if name := normalizeFindingName(in.Name); name != "" {
		add(FindingKeyName, "name:"+name)
	}
	if len(in.AssetIDs) > 0 && strings.TrimSpace(in.VulnClass) != "" {
		ids := append([]int64{}, in.AssetIDs...)
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, strconv.FormatInt(id, 10))
		}
		add(FindingKeyAssetClass, "asset_class:"+strings.Join(parts, ",")+":"+strings.ToLower(strings.TrimSpace(in.VulnClass)))
	}
	return out
}

func insertFindingKeysTx(tx *sql.Tx, findingID int64, keys []FindingKey) error {
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT INTO finding_keys(finding_id,dedup_key,kind) VALUES($1,$2,$3)
ON CONFLICT (finding_id,dedup_key) DO NOTHING`, findingID, k.Key, k.Kind); err != nil {
			return err
		}
	}
	return nil
}

// findFindingMergeTargetTx 按强键寻找自动合并目标（RecordFindingTx 事务流内调用）。
// 优先级：历史指纹精确匹配（老数据兼容，行为与移植前一致）> root > cve > legacy。
// endpoint/param 是弱键（rank 99），从不参与自动合并。只考虑同任务的
// pending/in_progress/confirmed 记录。
func findFindingMergeTargetTx(tx *sql.Tx, in RecordFindingInput, fp string, keys []FindingKey) (int64, error) {
	// 老数据兼容：finding_keys 上线前的历史记录按旧指纹精确匹配。
	if fp != "" && len(in.AssetIDs) > 0 {
		var id int64
		err := tx.QueryRow(`SELECT id FROM findings
WHERE task_id=$1 AND fingerprint=$2 AND status IN ('pending','in_progress','confirmed')
ORDER BY id LIMIT 1 FOR UPDATE`, in.TaskID, fp).Scan(&id)
		if err == nil {
			return id, nil
		}
		if err != sql.ErrNoRows {
			return 0, err
		}
	}

	strong := make([]FindingKey, 0, len(keys))
	for _, k := range keys {
		if strongFindingKeyRank(k.Kind) < 99 {
			strong = append(strong, k)
		}
	}
	if len(strong) == 0 {
		return 0, nil
	}
	args := []any{in.TaskID}
	ph := make([]string, 0, len(strong))
	for _, k := range strong {
		args = append(args, k.Key)
		ph = append(ph, fmt.Sprintf("$%d", len(args)))
	}
	q := `SELECT f.id, f.created_at,
       MIN(CASE fk.kind WHEN 'root' THEN 1 WHEN 'cve' THEN 2 WHEN 'legacy' THEN 5 ELSE 99 END) AS prio
FROM finding_keys fk
JOIN findings f ON f.id=fk.finding_id
WHERE f.task_id=$1 AND f.status IN ('pending','in_progress','confirmed')
  AND fk.kind NOT IN ('endpoint','param','name','asset_class')
  AND fk.dedup_key IN (` + strings.Join(ph, ",") + `)
GROUP BY f.id, f.created_at
ORDER BY prio, f.created_at, f.id
LIMIT 10`
	rows, err := tx.Query(q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var candidates []int64
	for rows.Next() {
		var id int64
		var created time.Time
		var prio int
		if err := rows.Scan(&id, &created, &prio); err != nil {
			return 0, err
		}
		candidates = append(candidates, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range candidates {
		var status string
		if err := tx.QueryRow(`SELECT status FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return 0, err
		}
		switch status {
		case FindingPending, FindingInProgress, FindingConfirmed:
			return id, nil
		}
	}
	return 0, nil
}

// mergeReportIntoTargetTx 把一次新上报合并进已有主记录：追加证据、严重度取
// 双方更高、并集资产、迁移流量、补身份键。源数据不落新行。
func mergeReportIntoTargetTx(tx *sql.Tx, targetID int64, in RecordFindingInput, fp string, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	keys := FindingDedupKeys(in, fp)
	var nodeID int64
	var status string
	if err := tx.QueryRow(`SELECT COALESCE(node_id,0), status FROM findings WHERE id=$1 FOR UPDATE`, targetID).Scan(&nodeID, &status); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	if status != FindingPending && status != FindingInProgress && status != FindingConfirmed {
		return nil, nil // 目标在事务内被并发翻成了终态，放弃合并由外层走新行
	}
	stamp := time.Now().UTC().Format("2006-01-02 15:04")
	appendix := fmt.Sprintf("\n\n--- 二次确认(worker=%s, %s UTC) ---\n%s", in.Worker, stamp, in.Evidence)

	// 严重度只升不降（critical > high > medium > low）。
	var curSeverity string
	if err := tx.QueryRow(`SELECT severity FROM findings WHERE id=$1`, targetID).Scan(&curSeverity); err != nil {
		return nil, err
	}
	// 资产并集直接在事务内读旧值→合并→写回（写失败放弃本次资产并集，不阻断证据合并）。
	_ = mergeFindingAssetsTx(tx, targetID, in.AssetIDs)
	root := normalizeRootCauseKey(in.RootCauseKey)
	if _, err := tx.Exec(`UPDATE findings SET evidence = evidence || $2,
  severity = CASE
    WHEN $3='critical' OR severity='critical' THEN 'critical'
    WHEN $3='high' OR severity='high' THEN 'high'
    WHEN $3='medium' OR severity='medium' THEN 'medium'
    WHEN $3='low' OR severity='low' THEN 'low'
    ELSE severity END,
  root_cause_key = CASE WHEN COALESCE(root_cause_key,'')='' THEN $4 ELSE root_cause_key END
WHERE id=$1`, targetID, appendix, in.Severity, root); err != nil {
		return nil, err
	}
	if in.IntentID > 0 && nodeID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
			SELECT $1,$2,$3,$4 WHERE NOT EXISTS(
				SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`,
			in.ExplorationID, in.IntentID, RelYields, nodeID); err != nil {
			return nil, err
		}
	}
	if err := insertFindingKeysTx(tx, targetID, keys); err != nil {
		return nil, err
	}
	if err := AddFindingTrafficTx(tx, targetID, prepared); err != nil {
		return nil, err
	}
	// 证据内容变了，同步节点 payload 的 evidence.poc 与 severity（与指纹去重
	// 旧路径一致：只并文字证据不更新节点会让发现 Tab 看到旧内容）。
	if nodeID > 0 {
		if _, err := tx.Exec(`UPDATE exploration_nodes
  SET payload = jsonb_set(
        jsonb_set(payload,'{severity}',to_jsonb($2::text),true),
        '{evidence,poc}', to_jsonb(COALESCE(payload->'evidence'->>'poc','') || $3), true)
WHERE id=$1`, nodeID, in.Severity, appendix); err != nil {
			return nil, err
		}
	}
	_ = bumpEvidenceVersionTx(tx, targetID)
	out := &RecordedFinding{FindingID: targetID, NodeID: nodeID, Duplicate: true}
	var err error
	out.Traffic, err = FindingTrafficTx(tx, targetID)
	return out, err
}

// mergeFindingAssetsTx 把本次上报的资产并进 findings.asset_ids（读旧值→并集→写回）。
func mergeFindingAssetsTx(tx *sql.Tx, findingID int64, add []int64) []int64 {
	var curJSON string
	if err := tx.QueryRow(`SELECT COALESCE(asset_ids::text,'[]') FROM findings WHERE id=$1`, findingID).Scan(&curJSON); err != nil {
		return append([]int64{}, add...)
	}
	var cur []int64
	_ = json.Unmarshal([]byte(curJSON), &cur)
	out := mergeInt64Slices(cur, add)
	b, _ := json.Marshal(out)
	if _, err := tx.Exec(`UPDATE findings SET asset_ids=$2::jsonb WHERE id=$1`, findingID, string(b)); err != nil {
		return out
	}
	return out
}

func mergeInt64Slices(existing, add []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(existing)+len(add))
	for _, id := range existing {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range add {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// weakFindingCandidatesTx 返回弱键命中的同任务候选 id（不含自身），只提示不合并。
func weakFindingCandidatesTx(tx *sql.Tx, findingID int64, keys []FindingKey) []int64 {
	var weak []string
	for _, k := range keys {
		switch k.Kind {
		case FindingKeyName, FindingKeyAssetClass, FindingKeyEndpoint, FindingKeyParam:
			weak = append(weak, k.Key)
		}
	}
	if len(weak) == 0 || findingID <= 0 {
		return nil
	}
	args := []any{findingID}
	ph := make([]string, 0, len(weak))
	for _, k := range weak {
		args = append(args, k)
		ph = append(ph, fmt.Sprintf("$%d", len(args)))
	}
	rows, err := tx.Query(`SELECT DISTINCT fk2.finding_id
FROM finding_keys fk1
JOIN finding_keys fk2 ON fk2.dedup_key=fk1.dedup_key AND fk2.finding_id<>fk1.finding_id
JOIN findings f ON f.id=fk2.finding_id
WHERE fk1.finding_id=$1 AND fk1.kind IN ('name','asset_class','endpoint','param')
  AND fk1.dedup_key IN (`+strings.Join(ph, ",")+`)
  AND f.status IN ('pending','in_progress','confirmed')
  AND f.task_id=(SELECT task_id FROM findings WHERE id=$1)
LIMIT 10`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// FindingMergeCandidates 返回弱键命中的同任务候选（不含自身与已合并/终态）。
// 只提示不自动合并；finding_cases 候选打分与前端「可能重复」提示共用。
func (d *DB) FindingMergeCandidates(ctx context.Context, findingID int64) ([]*DBFinding, error) {
	rows, err := d.Query(`SELECT DISTINCT fk2.finding_id
FROM finding_keys fk1
JOIN finding_keys fk2 ON fk2.dedup_key=fk1.dedup_key AND fk2.finding_id<>fk1.finding_id
JOIN findings f ON f.id=fk2.finding_id
WHERE fk1.finding_id=$1 AND fk1.kind IN ('name','asset_class','endpoint','param')
  AND f.status IN ('pending','in_progress','confirmed')
  AND f.task_id=(SELECT task_id FROM findings WHERE id=$1)
LIMIT 20`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0, 8)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*DBFinding, 0, len(ids))
	for _, id := range ids {
		f, err := d.GetFinding(id)
		if err != nil {
			return nil, err
		}
		if f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// BackfillFindingKeys 为历史 findings 补身份键（幂等、分批）。升级后旧数据也能
// 参与多键合并与候选提示；启动时调用，失败只记日志不阻塞。
func (d *DB) BackfillFindingKeys(ctx context.Context, limit int) error {
	if limit <= 0 {
		limit = 5000
	}
	rows, err := d.Query(`SELECT f.id, COALESCE(f.task_id,0), COALESCE(f.vulnclass,''), COALESCE(f.name,''),
COALESCE(f.severity,''), COALESCE(f.summary,''), COALESCE(f.evidence,''), COALESCE(f.worker,''),
COALESCE(f.asset_ids::text,'[]'), COALESCE(f.fingerprint,''), COALESCE(f.root_cause_key,'')
FROM findings f
WHERE NOT EXISTS (SELECT 1 FROM finding_keys k WHERE k.finding_id=f.id)
ORDER BY f.id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	type row struct {
		id                                      int64
		taskID                                  int64
		vulnclass, name, severity, summary, evi string
		worker, assetsJSON, fp, rootKey         string
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.taskID, &r.vulnclass, &r.name, &r.severity, &r.summary, &r.evi, &r.worker, &r.assetsJSON, &r.fp, &r.rootKey); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		for _, r := range batch {
			var assets []int64
			_ = json.Unmarshal([]byte(r.assetsJSON), &assets)
			in := RecordFindingInput{
				TaskID: r.taskID, VulnClass: NormalizeVulnClass(r.vulnclass), Name: r.name,
				Severity: r.severity, Summary: r.summary, Evidence: r.evi, Worker: r.worker,
				AssetIDs: assets, RootCauseKey: r.rootKey,
			}
			keys := FindingDedupKeys(in, r.fp)
			// 历史记录的指纹可能来自旧算法；始终保留 legacy 键。
			if r.fp != "" {
				found := false
				for _, k := range keys {
					if k.Kind == FindingKeyLegacy {
						found = true
					}
				}
				if !found {
					keys = append(keys, FindingKey{Key: "legacy:" + r.fp, Kind: FindingKeyLegacy})
				}
			}
			if err := insertFindingKeysTx(tx, r.id, keys); err != nil {
				return err
			}
		}
		return nil
	})
}
