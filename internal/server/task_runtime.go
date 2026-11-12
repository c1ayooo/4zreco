package server

import (
	"strconv"
	"time"
)

// A8 无成果止损的活跃秒数口径（移植自 ARTEX 0.3.29 server/task_runtime.go）。
// 段时间戳为 unix 秒；起点为 0 表示当前没有开放段。

// taskRunSeconds 从持久化段数据计算展示用活跃运行时长。仅当任务处于 running、
// 未暂停、未排队且有开放段时，才把 now−段起点计入。
func taskRunSeconds(active, segmentStarted, now int64, status string, paused, queued bool) int64 {
	if active < 0 {
		active = 0
	}
	if status == "running" && !paused && !queued && segmentStarted > 0 && now > segmentStarted {
		return active + now - segmentStarted
	}
	return active
}

// finalizeTaskRunSeconds 是数据库折叠转换的纯函数镜像，供确定性单测与需要在
// 不碰库的情况下推演一段生命周期的调用方使用。
func finalizeTaskRunSeconds(active, segmentStarted, now int64) (int64, int64) {
	if active < 0 {
		active = 0
	}
	if segmentStarted > 0 && now > segmentStarted {
		active += now - segmentStarted
	}
	return active, 0
}

// noResultRemaining 计算无成果止损的剩余时间：活跃秒数（排除 paused/queued，
// 复用任务运行时展示同一段数据）减去 no_result 基线，再与预算秒数作差。
func noResultRemaining(seconds int, state taskLifecycleState, now int64) time.Duration {
	runtime := taskRunSeconds(state.ActiveRunSeconds, state.RunSegmentStartedAt, now, state.Status, state.Paused, state.Queued)
	elapsed := max(int64(0), runtime-state.NoResultBaseSeconds)
	remaining := max(int64(0), int64(seconds)-elapsed)
	return time.Duration(remaining) * time.Second
}

// evaluateNoResultStop 是自动收尾的第四种判定的纯函数（其余三种见 auto_finish.go
// evaluateAutoFinish）：活跃运行满 seconds 且达标漏洞数少于 minimum → 止损收场。
// severity 阈值已由计数 SQL 折叠（低于阈值的漏洞不计入 count）。检查点已认领
// （checkedAt>0）时永不重复触发。
func evaluateNoResultStop(runtimeSeconds, count, seconds, minimum int64, checkedAt int64) (detail string, ok bool) {
	if seconds <= 0 || checkedAt > 0 {
		return "", false
	}
	elapsed := max(int64(0), runtimeSeconds)
	if elapsed < seconds {
		return "", false
	}
	if count >= max(int64(1), minimum) {
		return "", false
	}
	return "无成果止损：活跃运行 " + (time.Duration(elapsed) * time.Second).String() +
		"，达标漏洞 " + strconv.FormatInt(count, 10) + "/" + strconv.FormatInt(max(int64(1), minimum), 10) +
		"，任务自动停止", true
}
