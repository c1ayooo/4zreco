package db

// 会话/任务自动标题（auto_title，移植自 ARTEX 0.3.29 A2）的 settings 键。
// 两个开关默认关；判定/清洗逻辑在 internal/server/auto_title.go（纯函数，不进内核）。
const (
	SettingTaskAutoTitle = "task_auto_title_enabled"
	SettingChatAutoTitle = "chat_auto_title_enabled"
)
