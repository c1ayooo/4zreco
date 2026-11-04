package config

import "path/filepath"

// Paths 是全部运行时目录的**唯一解析点**：所有「根目录 + 字面量子目录」的拼接
// 都必须走这里的方法，禁止在业务代码里再手写 filepath.Join(root, "字面量")。
// 此前 18 处散落的拼接点（transcripts 拼了 3 处、evidence 每次现建、保护名单是
// 硬编码字符串……）已全部收敛到本文件；改目录布局只动这一个文件。
//
// 两个根：
//   - Base：可执行文件所在目录（go run 回落 CWD，见 BaseDir）。jwt.key、skills/、
//     nuclei-templates/ 这类「随分发物走」的资产放这里。
//   - Data：数据根（-data flag，默认 <Base>/data）。任务工作区、流量库、证据、
//     会话转录等运行时产物放这里，工作空间文件管理器以它为根。
//
// 约束：构造（NewPaths）不得有任何副作用（不 MkdirAll、不读 env）——测试会大量
// 构造它；目录创建由各使用方负责。Skills 是唯一由外部解析后注入的字段
// （config.SkillDir() 带 MkdirAll 副作用，只有主入口 main.go 调它一次）。
type Paths struct {
	Base   string // 可执行文件目录（绝对路径）
	Data   string // 数据根（绝对路径）
	Skills string // skill 根目录（主入口注入；零值 = 未配置）
}

// NewPaths 以 BaseDir() 为 Base、dataDir 为 Data 构造解析器（两者都绝对化）。
func NewPaths(dataDir string) Paths {
	return Paths{
		Base: abs(BaseDir()),
		Data: abs(dataDir),
	}
}

// DerivePaths 供测试直构 Manager/Server 时按已知数据根现场推导（Base 仍取
// BaseDir()——测试里它指向包目录，但测试只消费 Data 派生方法，Base 派生方法
// （jwt/skills/nuclei）不会被打到磁盘）。
func DerivePaths(dataRoot string) Paths {
	return NewPaths(dataRoot)
}

func abs(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// ── Base 派生（随分发物走的资产） ────────────────────────────────────────

// JWTKeyPath 是 JWT 签名密钥位置（Base 下，绝不进可浏览的 Data 工作区）。
func (p Paths) JWTKeyPath() string { return filepath.Join(p.Base, "jwt.key") }

// LegacyJWTKeyPath 是 v0.4.x 之前 jwt.key 的旧位置（一次性迁出用）。
func (p Paths) LegacyJWTKeyPath() string { return filepath.Join(p.Data, "jwt.key") }

// NucleiTemplates 是 nuclei 模板树的落盘位置：项目目录内部（Base 下，与 skills/
// 同级），而不是 Data 数据目录。自动下载/更新（git clone + 6h pull）写到这里。
func (p Paths) NucleiTemplates() string { return filepath.Join(p.Base, "nuclei-templates") }

// LegacyNucleiTemplates 是 v0.4.x 之前模板树的旧位置（一次性迁移用）。
func (p Paths) LegacyNucleiTemplates() string { return filepath.Join(p.Data, "nuclei-templates") }

// ── Data 派生（运行时产物，工作空间浏览器以 Data 为根） ────────────────────

// ProtectedWorkspaceDirs 是工作空间里**不可删除**的系统目录名单（相对 Data 的
// 字面量）。nuclei-templates 已移到 Base 下、不在工作区视野内，故不再入列。
func (p Paths) ProtectedWorkspaceDirs() []string { return []string{"traffic", "evidence"} }

func (p Paths) Traffic() string     { return filepath.Join(p.Data, "traffic") }
func (p Paths) Evidence() string    { return filepath.Join(p.Data, "evidence") }
func (p Paths) Transcripts() string { return filepath.Join(p.Data, "transcripts") }
func (p Paths) NoaRoot() string     { return filepath.Join(p.Data, "noa") }

// SignaturesDir / HoneypotSignatures 是蜜罐签名库的位置（可选覆盖文件，缺失回落
// 内嵌库）。
func (p Paths) SignaturesDir() string        { return filepath.Join(p.Data, "signatures") }
func (p Paths) HoneypotSignatures() string   { return filepath.Join(p.SignaturesDir(), "honeypot.json") }

// DeleteStaging 是任务删除的两阶段文件暂存区（隐藏目录，工作区不可见）。
func (p Paths) DeleteStaging() string { return filepath.Join(p.Data, ".delete-staging") }

// ArchivesRoot / TaskArchivesRoot 是任务冷归档的落盘位置。
func (p Paths) ArchivesRoot() string     { return filepath.Join(p.Data, "archives") }
func (p Paths) TaskArchivesRoot() string { return filepath.Join(p.ArchivesRoot(), "tasks") }

// ── 任务 / 会话工作区（tasks|sessions|drafts 三棵树对称） ──────────────────
//
// tasks/<id>   主 agent / worker 的工作目录；uploads、artifacts 是其内部子布局
// sessions/<id> 对话 agent 的工作目录
// drafts/<id>  建任务前的上传暂存（任务尚无 ID）

func (p Paths) TasksRoot() string    { return filepath.Join(p.Data, "tasks") }
func (p Paths) SessionsRoot() string { return filepath.Join(p.Data, "sessions") }
func (p Paths) DraftsRoot() string   { return filepath.Join(p.Data, "drafts") }

func (p Paths) TaskDir(taskID string) string      { return filepath.Join(p.TasksRoot(), taskID) }
func (p Paths) TaskUploads(taskID string) string  { return filepath.Join(p.TaskDir(taskID), "uploads") }
func (p Paths) SessionDir(id string) string       { return filepath.Join(p.SessionsRoot(), id) }
func (p Paths) SessionUploads(id string) string   { return filepath.Join(p.SessionDir(id), "uploads") }
func (p Paths) DraftUploads(id string) string     { return filepath.Join(p.DraftsRoot(), id, "uploads") }
