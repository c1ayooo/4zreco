package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreco/internal/listener"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// 回连接收器工具（红队杀伤链的 C2 前置）：接住反弹 shell / OOB 回连并留证。
// 设计边界见 listener 包注释——本工具集只管「接住 + 看到会话」，交互式 shell
// 由 agent 用 Bash 里的 nc/socat 自行完成。
//
// 审批语义：启停走拦截规则「[内置] 启停回连接收器」（ask，人工确认——开放
// 本机端口是平台能力边界变更）；查询会话是只读操作不走拦截。

var listenerMgr *listener.Manager

// ConnectBack 是给 agent 的回连参数（payload 的 LHOST/LPORT）。
type ConnectBack struct {
	Mode  string `json:"mode"`
	LHOST string `json:"lhost"`
	LPORT int    `json:"lport"`
	Via   string `json:"via,omitempty"`
}

// connectBackFn 由 server 注入：把监听端口解析成目标应连的地址
// （direct=本机网卡；ssh/manual=公网中转）。nil=未注入（回落 127.0.0.1）。
var connectBackFn func(port int) ConnectBack

// SetConnectBackResolver wires the C2 egress resolver.
func SetConnectBackResolver(fn func(port int) ConnectBack) { connectBackFn = fn }

// resolveConnectBack 解析回连地址；无注入时用保守回退。
func resolveConnectBack(port int) ConnectBack {
	if connectBackFn != nil {
		return connectBackFn(port)
	}
	return ConnectBack{Mode: "direct", LHOST: "127.0.0.1", LPORT: port,
		Via: "未配置 C2 出口，回退 127.0.0.1（同机测试才可达）"}
}

// SetListenerManager wires the process-wide callback-listener manager.
func SetListenerManager(m *listener.Manager) { listenerMgr = m }

func listenerUnavailable() (actool.Result, bool) {
	if listenerMgr == nil {
		return actool.Errorf("回连接收器未启用（服务端未初始化）"), true
	}
	return actool.Result{}, false
}

// listenerStart 起一个监听器（ask 门在拦截规则层）。
func (t *ToolSet) listenerStart() actool.CoreTool {
	return writeTool(
		"listener_start",
		"启动一个【TCP 回连接收器】：在本机开放端口接住反弹 shell / OOB 回连，记录每个会话的来源、时间与捕获内容（前 64KB）。适合：拿到 RCE 后先起监听再触发回连、OOB 盲注验证、多会话归集。端口限 1024-65535。交互式 shell 请配合 Bash 里的 nc/socat 使用（本工具只负责接住与留证）。",
		obj(map[string]any{
			"name": str("监听器名称（字母数字-_.，全局唯一），如 task1-shell"),
			"port": intp("监听端口（1024-65535），如 4444"),
		}, "name", "port"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := listenerUnavailable(); un {
				return r, nil
			}
			var a struct {
				Name string `json:"name"`
				Port int    `json:"port"`
			}
			_ = json.Unmarshal(in, &a)
			l, err := listenerMgr.Start(strings.TrimSpace(a.Name), a.Port)
			if err != nil {
				return actool.Errorf("启动失败: " + err.Error()), nil
			}
			cb := resolveConnectBack(l.Port)
			return jsonResult(map[string]any{
				"name":         l.Name,
				"port":         l.Port,
				"started_at":   l.StartedAt,
				"connect_back": cb,
				"note": "监听已启动。触发目标回连时 LHOST=" + cb.LHOST +
					"、LPORT=" + fmt.Sprint(cb.LPORT) +
					"（以此为准，勿用本机地址）；回连后用 listener_sessions 查看会话；交互式操作用 Bash 的 nc/socat 连本机端口。",
			})
		},
	)
}

// listenerStop 停监听器并带走最终会话快照。
func (t *ToolSet) listenerStop() actool.CoreTool {
	return writeTool(
		"listener_stop",
		"停止一个回连接收器，返回其全部会话记录（来源/时间/捕获内容）——收尾归档或换端口时用。",
		obj(map[string]any{
			"name": str("要停止的监听器名称"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := listenerUnavailable(); un {
				return r, nil
			}
			var a struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			sessions, err := listenerMgr.Stop(strings.TrimSpace(a.Name))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"stopped":  a.Name,
				"sessions": sessions,
			})
		},
	)
}

// listenerSessions 查看监听器捕获的会话（只读）。
func (t *ToolSet) listenerSessions() actool.CoreTool {
	return readTool(
		"listener_sessions",
		"查看回连接收器捕获的会话列表：每个回连的来源 IP:端口、连接时间、字节量与捕获内容预览。拿到会话后可继续用 Bash 深入（如 socat/nc 接管），并把关键内容作为证据上报。",
		obj(map[string]any{
			"name": str("监听器名称"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if r, un := listenerUnavailable(); un {
				return r, nil
			}
			var a struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			sessions, ok := listenerMgr.Get(strings.TrimSpace(a.Name))
			if !ok {
				return actool.Errorf(fmt.Sprintf("监听器 %q 不存在（用 listener_start 先启动）", a.Name)), nil
			}
			return jsonResult(map[string]any{
				"name":     a.Name,
				"sessions": sessions,
				"note":     "preview 是每个会话捕获的前 64KB；交互式接管用 Bash nc/socat 连本机端口",
			})
		},
	)
}
