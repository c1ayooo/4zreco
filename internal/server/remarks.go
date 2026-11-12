package server

import "github.com/c1ayooo/4zreco/internal/db"

// normalizeRemark trims and bounds a task/template remark against the shared
// limit (ARTEX 移植 A1)；校验逻辑单点在 db.NormalizeTaskRemark。
func normalizeRemark(value string) (string, error) {
	return db.NormalizeTaskRemark(value)
}
