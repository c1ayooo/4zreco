package db

import (
	"fmt"
	"strings"
)

// ═══ 上游 0.4.63：授权边界守卫（跨任务串资产防线的第④层）═══
//
// 现网复盘（客户环境，任务 4）：task 1/2/3 在打 dkfvtg.cn，新任务 4 在打 aibuji.com，
// 但 worker 把并行任务上下文里的 JeecgBoot 线索安到了 aibuji.com 头上（fact #1901 写成
// observed/confirmed），planner 又基于这条未复核事实级联派发，最后 finding 的 asset_ids
// 挂上了 dkfvtg 的资产——授权边界从头到尾都是软约束。
//
// 这组查询把「资产对某任务是什么关系」变成确定性答案，供写回锚定校验使用：
//   own    —— 匹配本任务自己的 task_scope，或资产本就由本任务发现/登记（task_ids 包含本任务）
//   source —— 只匹配来源/继承任务（task_relations）的 scope，或只被来源任务登记
//   foreign—— 两边都不沾（完全越界）
//
// 语义（写回锚定校验，见 internal/agent 的 scopeGuardError）：
//   own    → 可锚定；
//   source → 拒绝（继承范围只读是双图设计的一贯口径；确属本任务授权时用
//            add_task_scope 显式纳入）；
//   foreign→ 一律拒绝。
//
// 注意：4zreco 的项目范围（project_scope 种成 task_scope source='project'）是
// 组织定义非闸门，本文件不改 insert_assets 的资产拦截/认领语义，只服务
// fact/intelligence/finding 写回时的 asset_ids 锚定校验。

// ownScopeTargetCTE 只看本任务自己声明的 scope（不含来源任务）。
const ownScopeTargetCTE = `
own_scope_assets AS (
  SELECT DISTINCT a.id
  FROM assets a
  JOIN task_scope ts ON (
       (ts.kind='company'     AND a.company_id = ts.company_id)
    OR (ts.kind='root_domain' AND a.root_domain = ts.domain)
    OR (ts.kind='subdomain'   AND a.domain = ts.domain)
    OR (ts.kind IN ('ip','cidr') AND (ts.net >>= try_inet(a.ip) OR ts.net >>= try_inet(a.domain)))
    OR (ts.kind='icp' AND (
         lower(regexp_replace(COALESCE(a.icp,''), '[[:space:]]+', '', 'g')) = ts.value
         OR lower(regexp_replace(COALESCE(a.app_icp,''), '[[:space:]]+', '', 'g')) = ts.value
       ))
  )
  WHERE ts.task_id=$1
)`

// sourceScopeTargetCTE 只看来源/继承任务（task_relations）声明的 scope。
const sourceScopeTargetCTE = `
source_scope_assets AS (
  SELECT DISTINCT a.id
  FROM assets a
  JOIN task_scope ts ON (
       (ts.kind='company'     AND a.company_id = ts.company_id)
    OR (ts.kind='root_domain' AND a.root_domain = ts.domain)
    OR (ts.kind='subdomain'   AND a.domain = ts.domain)
    OR (ts.kind IN ('ip','cidr') AND (ts.net >>= try_inet(a.ip) OR ts.net >>= try_inet(a.domain)))
    OR (ts.kind='icp' AND (
         lower(regexp_replace(COALESCE(a.icp,''), '[[:space:]]+', '', 'g')) = ts.value
         OR lower(regexp_replace(COALESCE(a.app_icp,''), '[[:space:]]+', '', 'g')) = ts.value
       ))
  )
  JOIN task_relations relation ON relation.source_task_id = ts.task_id
  WHERE relation.task_id=$1
)`

// AssetScopeClass 是单个资产对某任务的归属分类。
type AssetScopeClass string

const (
	ScopeClassOwn     AssetScopeClass = "own"
	ScopeClassSource  AssetScopeClass = "source"
	ScopeClassForeign AssetScopeClass = "foreign"
)

// ClassifyAssetsForTask 把 ids 按 own/source/foreign 分类。查询失败时返回错误，
// 调用方决定失败策略（写回锚定校验建议 fail-open 但打日志，避免把正常任务全部卡死）。
func (s *AssetStore) ClassifyAssetsForTask(taskID int64, ids []int64) (own, source, foreign []int64, err error) {
	if len(ids) == 0 {
		return nil, nil, nil, nil
	}
	ph := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, taskID)
	for i, id := range ids {
		ph[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	q := `WITH ` + ownScopeTargetCTE + `, ` + sourceScopeTargetCTE + `
SELECT id,
  CASE
    WHEN id IN (SELECT id FROM own_scope_assets) OR $1::bigint = ANY(task_ids) THEN 'own'
    WHEN id IN (SELECT id FROM source_scope_assets)
      OR EXISTS (SELECT 1
                 FROM unnest(task_ids) u
                 JOIN tasks st ON st.id = u AND st.deleted_at IS NULL
                 JOIN task_relations relation ON relation.source_task_id = st.id
                 WHERE relation.task_id = $1)
      THEN 'source'
    ELSE 'foreign'
  END AS cls
FROM assets WHERE id IN (` + strings.Join(ph, ",") + `)`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var cls string
		if err := rows.Scan(&id, &cls); err != nil {
			return nil, nil, nil, err
		}
		switch AssetScopeClass(cls) {
		case ScopeClassOwn:
			own = append(own, id)
		case ScopeClassSource:
			source = append(source, id)
		default:
			foreign = append(foreign, id)
		}
	}
	return own, source, foreign, rows.Err()
}

// FindForeignAssetForTask 在「插入/认领资产」前用身份字段（域名/IP/URL 前缀）反查：
// 是否存在一个【不属于本任务】（task_ids 不含本任务）且【不在本任务自有 scope】的既有资产。
// 命中说明这次插入会把别人的资产悄悄认领进本任务，返回该资产的 id 与归属任务 ids；
// 未命中返回 nil。
//
// 4zreco 当前只在 fact/intelligence/finding 写回锚定校验中使用 ClassifyAssetsForTask；
// 本查询保留为 db 层公共设施（含测试），不接入 insert_assets 的资产拦截语义。
func (s *AssetStore) FindForeignAssetForTask(taskID int64, domains, ips, urls []string) (id int64, ownerTasks string, err error) {
	if len(domains) == 0 && len(ips) == 0 && len(urls) == 0 {
		return 0, "", nil
	}
	if len(domains) > 16 {
		domains = domains[:16]
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	if len(urls) > 16 {
		urls = urls[:16]
	}
	q := `WITH ` + ownScopeTargetCTE + `
SELECT a.id, COALESCE(array_to_string(a.task_ids, ','), '')
FROM assets a
WHERE NOT ($1::bigint = ANY(a.task_ids))
  AND a.id NOT IN (SELECT id FROM own_scope_assets)
  AND (
        COALESCE(a.domain,'') = ANY($2::text[])
     OR COALESCE(a.root_domain,'') = ANY($2::text[])
     OR (cardinality($3::text[]) > 0 AND COALESCE(a.ip,'') <> ''
         AND EXISTS (SELECT 1 FROM unnest($3::text[]) u WHERE try_inet(a.ip) = try_inet(u)))
     OR EXISTS (SELECT 1 FROM unnest($4::text[]) u
                WHERE u<>'' AND COALESCE(a.url,'')<>''
                  AND (left(a.url, length(u))=u OR left(u, length(a.url))=a.url))
  )
ORDER BY a.id LIMIT 1`
	err = s.db.QueryRow(q, taskID, domains, ips, urls).Scan(&id, &ownerTasks)
	if err != nil {
		return 0, "", nil // no row → 未命中，不视为错误
	}
	return id, ownerTasks, nil
}
