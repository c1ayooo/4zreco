package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/c1ayooo/4zreco/internal/db"
)

// ArtifactRecorder 由 host（server）实现：校验路径边界与限额、复制到任务附件
// 目录并落库。agent 只负责"把工作目录里的文件交出去"，不直接写附件库。
type ArtifactRecorder interface {
	RecordArtifact(taskID, findingID int64, runDir, relPath, name, kind, sourceURL, note string) (*db.TaskArtifact, error)
}

// ListTaskArtifacts 是 host 注入的附件列表读取（agent 工具用）。nil = 不可用。
var ListTaskArtifacts func(taskID string) ([]db.TaskArtifact, error)

// FindingTaskID 由 host 注入：按漏洞 ID 反查所属任务（v0.4.20）。
// reporter 的 chat 工具集没有任务上下文，靠模型传 finding_id 定位任务。
var FindingTaskID func(findingID int64) (string, error)

// artifactGuidance 注入 worker system prompt：截图与证据存档的时机纪律
// （v0.5.0）。报告要"有照片"，前提是 worker 在正确时刻截图并登记。
const artifactGuidance = `

━━ 证据附件（截图 / 数据样本 / 日志）━━
确认漏洞或拿到关键证据后，把**能证明结论的原始材料**登记为任务附件：
- 截图：用 browser/playwright 工具访问目标页面截图（登录后的数据列表、后台界面、IDOR 越权页、上传/下载结果、命令回显页面），或用 chromium headless 兜底：
  ` + "`chromium --headless --disable-gpu --screenshot=<工作目录内路径>.png --window-size=1440,900 '<URL>'`" + `
  截图后用 save_evidence 登记，note 写清"哪个系统的什么页面、证明什么"（这是报告图注）。
- 数据样本：扒到的敏感数据只存**证明性样本**（如前 20 条记录/前 50 行），不要存全量 PII；全量数据留在工作目录供分析，不随报告分发。
- 日志/HTML/JSON：命令输出、接口原始响应、页面源码，存成 .txt/.json/.html 再登记。
- 每个漏洞至少登记 1 张关键截图（能截到的话）；截不到（无浏览器/非 HTTP）就跳过并在证据里说明原因，不要伪造。
- 登记时传 finding_id（report_finding 返回的独立漏洞 ID）：该漏洞的详情页与单漏洞报告才会展示这张图；任务级材料（目标首页等）不传。

━━ 存储桶 / 文件读取 / 上传类漏洞：照片就是证据 ━━
只写“拿到了存储桶 / 能读文件”不算证明，**必须把抓到的文件本身留成证据**：
1. 从 bucket/接口下载 5–9 个关键文件样本（照片优先：收款收据、签呈表、报销单、聊天截图、证件照等），存到工作目录（文件名 URL 编码的先解码成可读名）。
2. 展示方式自己判断（**少拼、按比例、高清**；3×3 小格拼图会看不清细节，不要用）：
   - 1 张且清晰 → 单图原分辨率登记（note 写清 bucket/路径 + 文件名 + 证明什么）。
   - 2 张 → 并排拼一张（每张按比例缩到高 1000）。
   - 3–4 张 → 2×2 拼一张（每张按比例缩到高 800）。
   - 超过 4 张 → 分多张拼图（每张 2–4 张，文件名 montage-1.png、montage-2.png…），证明“批量”再补一张文件清单（ls 输出存 .txt）。
   - 竖长截图（宽高比 < 1:1.6、以文字为主）→ 单独登记或 2 张并排，拼图时放大档（高 1200），不要塞进小格。
   - 每张图底部叠**真实文件名水印**（URL 编码先解码；中文字体用 ` + "`/usr/share/fonts/gongwen/仿宋_GB2312.ttf`" + `）：
   示例命令（2 张并排；3–4 张同理：两两 +append 后再 -append）：
font=/usr/share/fonts/gongwen/仿宋_GB2312.ttf
for f in a.jpg b.jpg; do
  label=$(basename "$f")
  magick "$f" -auto-orient -resize x1000     -gravity south -background '#000000a8' -splice 0x36     -fill white -pointsize 22 -font "$font"     -annotate +0+9 "$label" "wm_$(basename "$f")"
done
magick wm_a.jpg wm_b.jpg +append montage.png
   - 单图叠水印：
     ` + "`magick in.jpg -gravity south -background '#000000a8' -splice 0x36 -fill white -pointsize 22 -font /usr/share/fonts/gongwen/仿宋_GB2312.ttf -annotate +0+9 'filename.jpg' out.png`" + `
   - 含身份证号/人脸等敏感信息但必须证明真实性的，先做模糊处理再登记（` + "`magick in.jpg -region 60%x25%+20%+40% -blur 0x12 out.jpg`" + ` 之类），并在 note 说明脱敏位置。
3. 登记时带 source_url（bucket 的对象 URL）与 finding_id；note 里写明样本数量。报告里用 ![说明](artifact:<id>) 引用，图注写清 bucket/文件与“样本 N 张”。`

// saveEvidence 把工作目录里的文件登记为任务附件。
func (t *ToolSet) saveEvidence() actool.CoreTool {
	return writeTool("save_evidence",
		"把工作目录里的证据文件登记为任务附件（截图 / 数据样本 / 日志 / HTML / JSON），随报告导出成证据包。默认只存证明性样本：敏感数据只存前 20 条左右，不要存全量 PII。同一文件重复登记会去重。",
		obj(map[string]any{
			"path":       str("工作目录内的相对路径（如 shots/login-userlist.png）"),
			"name":       str("可选：展示名（含扩展名）；省略用文件名"),
			"kind":       str("可选：image|data|log|html|auto（默认按扩展名推断）"),
			"source_url": str("可选：采集来源 URL"),
			"note":       str("说明：证明什么（截图会作为报告图注，务必具体）"),
			"finding_id": map[string]any{"type": "integer", "description": "可选：这块证据证明哪个漏洞（report_finding 返回的 finding_id）。带上后该漏洞详情页与单漏洞报告会展示这张图"},
		}, "path"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path, Name, Kind, SourceURL, Note string
				FindingID                         int64 `json:"finding_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.artifactRecorder == nil {
				return actool.Errorf("证据附件存储不可用（当前运行环境未启用）"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("save_evidence 需要任务上下文"), nil
			}
			if t.runDir == "" {
				return actool.Errorf("save_evidence 需要当前运行目录（内部未注入）"), nil
			}
			rec, err := t.artifactRecorder.RecordArtifact(t.taskID, a.FindingID, t.runDir, a.Path, a.Name, a.Kind, a.SourceURL, a.Note)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, _ := json.Marshal(map[string]any{
				"artifact_id": rec.ID, "name": rec.Name, "kind": rec.Kind,
				"size_bytes": rec.SizeBytes, "note": rec.Note,
			})
			return actool.Text(fmt.Sprintf("evidence saved: artifact %d\n%s\n报告撰写时可用 ![说明](artifact:%d) 引用这张图。", rec.ID, out, rec.ID)), nil
		})
}

// listArtifacts 列出本任务已登记的证据附件（worker 核对、reporter 引用用）。
// reporter 没有任务上下文，可传 finding_id 让工具反查所属任务（v0.4.20）。
func (t *ToolSet) listArtifacts() actool.CoreTool {
	return readTool("list_artifacts",
		"列出本任务已登记的证据附件（id/名称/类型/大小/说明/来源）。撰写报告时用 ![图注](artifact:<id>) 把图片插进报告。reporter 可传 finding_id 以定位该漏洞所属任务的附件。",
		obj(map[string]any{
			"finding_id": map[string]any{"type": "integer", "description": "可选：当前漏洞 ID；reporter 用它定位所属任务的附件清单"},
		}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64 `json:"finding_id"`
			}
			_ = json.Unmarshal(in, &a)
			taskID := t.taskID
			if taskID <= 0 && a.FindingID > 0 && FindingTaskID != nil {
				if tid, err := FindingTaskID(a.FindingID); err == nil && tid != "" {
					if n, err := strconv.ParseInt(tid, 10, 64); err == nil {
						taskID = n
					}
				}
			}
			if ListTaskArtifacts == nil || taskID <= 0 {
				return actool.Text("[]"), nil
			}
			list, err := ListTaskArtifacts(fmt.Sprint(taskID))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, _ := json.Marshal(map[string]any{"artifacts": list})
			return actool.Text(string(out)), nil
		})
}
