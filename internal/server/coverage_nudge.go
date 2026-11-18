package server

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreco/internal/agent"
	"github.com/c1ayooo/4zreco/internal/db"
)

// 覆盖矩阵缺口提醒（U5，上游 v0.4.63）。
//
// 上游复盘（任务 #5/#6）：planner 提示词里已经写了 10 类漏洞覆盖矩阵，但弱模型
// 实际派单仍集中在它熟悉的几类——任务 #6 的 16 条意图里 sqli 0、xss 0、rce 0，
// authz 却占 13 条。提示词约束不住，就在引擎侧补一层确定性的提醒：发现某类完全
// 没被任何意图提到，就唤醒 planner 一次，点名要求派该类意图（每类每任务 6 小时
// 最多提醒一次，避免刷屏）。
var coverageClasses = []struct {
	key   string
	label string
	re    string // 意图文本命中即视为已覆盖
	tip   string
}{
	{"sqli", "SQL 注入", `sql注入|sqli|sqlmap`, "对带参数的接口（GET 参数 / POST 表单 / JSON 字段）做只读注入探测，至少覆盖登录/查询/详情各 1 个端点。"},
	{"xss", "XSS/模板注入", `xss|跨站|模板注入`, "对回显用户输入的页面与接口验证反射/存储型 XSS。"},
	{"ssrf", "SSRF/回连", `ssrf|服务端请求伪造|回连`, "检查 URL 参数、图片代理、webhook、导出回调；用 listener 验证回连。"},
	{"upload", "文件上传/解析", `上传|upload`, "找上传接口，测类型/后缀/内容/路径绕过（只验证能力，不落地后门）。"},
	{"rce", "命令执行/反序列化", `命令执行|rce|反序列化|代码执行`, "按组件指纹（框架/中间件版本）查 CVE 后实际触发；无组件线索就跳过并说明。"},
	{"dirscan", "目录/路径发现", `目录|路径爆破|ffuf|gobuster|dirsearch`, "对主站/后台/网关跑一次目录发现，结果写回资产。"},
}

// missingCoverageClasses 返回尚未被任何意图文本覆盖的类别 key（按声明顺序）。
// 纯函数——表驱动测试的判定面。
func missingCoverageClasses(intentTexts []string) []string {
	joined := strings.ToLower(strings.Join(intentTexts, "\n"))
	var out []string
	for _, c := range coverageClasses {
		re := regexp.MustCompile(c.re)
		if !re.MatchString(joined) {
			out = append(out, c.key)
		}
	}
	return out
}

func coverageClassByKey(key string) (label, tip string, ok bool) {
	for _, c := range coverageClasses {
		if c.key == key {
			return c.label, c.tip, true
		}
	}
	return "", "", false
}

// nudgeCoverageGaps 在 planner 一轮结束后调用：某类完全没被提到就唤醒一次 planner。
// 每类每任务 6 小时内只提醒一次；任务无任何资产时不提醒（还没到漏洞阶段）。
func (e *Engine) nudgeCoverageGaps(t *Task) {
	if e.m == nil || e.m.pg == nil || t == nil || t.Store == nil {
		return
	}
	var assets int
	_ = e.m.pg.QueryRow(`SELECT count(*) FROM task_asset_links WHERE task_id=$1`, t.ID).Scan(&assets)
	if assets == 0 {
		return
	}
	intents, err := t.Store.ListByKind(db.KindIntent, 1000)
	if err != nil || len(intents) < 5 {
		// 意图太少（刚开局/测试场景）时先不提醒：此时还没到谈"覆盖缺口"的阶段。
		return
	}
	texts := make([]string, 0, len(intents))
	for _, n := range intents {
		texts = append(texts, string(n.Payload))
	}
	for _, key := range missingCoverageClasses(texts) {
		settingKey := fmt.Sprintf("coverage_nudge_%s_%s", t.ID, key)
		if v, ok, _ := e.m.pg.GetSetting(settingKey); ok {
			// 6 小时内提醒过就跳过；老版本存的 "1" 解析失败 → 视为很久以前，可再提醒。
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil && time.Since(time.Unix(ts, 0)) < 6*time.Hour {
				continue
			}
		}
		label, tip, ok := coverageClassByKey(key)
		if !ok {
			continue
		}
		msg := fmt.Sprintf("覆盖矩阵缺口：本任务至今没有任何【%s】类意图。请派 1 条只做该类的意图——%s"+
			" summary 里写清目标 endpoint 与工具/判据；若该类对本目标明确不适用，派一条极小确认意图或让 worker 用 fact 说明不适用，不要静默跳过。",
			label, tip)
		t.trigMu.Lock()
		t.pendingTriggers = append(t.pendingTriggers, agent.TriggerEvent{Kind: "coverage_gap", Detail: msg})
		t.trigMu.Unlock()
		_ = e.m.pg.SetSetting(settingKey, strconv.FormatInt(time.Now().Unix(), 10))
		log.Printf("[coverage] task %s 缺口提醒：%s", t.ID, label)
		t.Notify()
	}
}
