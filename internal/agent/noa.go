package agent

import (
	"log"
)

// noaFallbackWarn 是 noa 的占位：noa 是已退役的 norma agentcore 生态的实验压缩
// 机制（noaadapter），P4 删 norma 时随之移除，尚未随 eino 内核移植（刀⑤级增量）。
// 用户在系统设置里开了开关时告警并回退内置 compaction——与当年接入失败时的回退
// 同语义。开关解析器（SetNoaEnabled 注入的 noaEnabledFn）保留，移植后直接替换
// 本函数为真正的接入点。
func noaFallbackWarn(onWarn func(string), enabled func() bool, session string) {
	if enabled == nil || !enabled() {
		return
	}
	msg := "noa 压缩已随 norma 退役，本次运行回退内置 compaction"
	if onWarn != nil {
		onWarn(msg)
	} else {
		log.Printf("[noa] %s: %s", session, msg)
	}
}
