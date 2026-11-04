// 宿主工具体检 API:返回本机 PATH 里的渗透工具可用性清单。
// 二进制部署的"系统有什么就能用什么"显式化——前端在系统页展示,
// agent 侧同一份数据经 graph_overview 注入。
package server

import (
	"net/http"
	"os"

	"github.com/c1ayooo/4zreco/internal/hosttools"
)

func (s *Server) toolsInventory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"tools":       hosttools.Inventory(),
		"summary":     hosttools.Summary(),
		"deploy_mode": deployMode(),
	})
}

// deployMode 当前部署形态提示:Docker 容器内工具集固定,宿主二进制形态
// 工具随系统装卸。检测依据:Dockerfile 写入的标记文件。
func deployMode() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	return "host"
}
