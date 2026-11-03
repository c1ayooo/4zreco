package server

import (
	"fmt"
	"sort"
	"strings"
)

// 这里是 DB CHECK 约束的前置校验。
//
// 为什么要在前置校验而不是等数据库报错：DB 约束违反会以 500 + SQLSTATE 23514
// 的形式甩给用户，前端看到的是「服务器内部错误」，而不是「你填的 format 不对」。
// 契约测试也直接暴露了这一点——POST /api/llm/profiles 与 POST /api/mcp 在空
// 参数下返回 5xx，而 4xx 才是调用方能处理的答案。
//
// 合法值必须与 db/schema.sql 里的 CHECK 保持一致：
//   llm_profiles_format_check     CHECK (format IN ('openai','anthropic','openai-responses'))
//   mcp_servers_transport_check   CHECK (transport IN ('stdio','http','sse'))

// validLLMProfileFormats 与 llm_profiles_format_check 一致。
var validLLMProfileFormats = map[string]bool{
	"openai":          true,
	"anthropic":       true,
	"openai-responses": true,
}

// validMCPTransports 与 mcp_servers_transport_check 一致。
var validMCPTransports = map[string]bool{
	"stdio": true,
	"http":  true,
	"sse":   true,
}

// checkEnum 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func checkEnum(field, value string, allowed map[string]bool) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return fmt.Sprintf("%s 不能为空", field)
	}
	if !allowed[v] {
		keys := make([]string, 0, len(allowed))
		for k := range allowed {
			keys = append(keys, k)
		}
		// 固定顺序，避免每次报错文案都不一样。
		sort.Strings(keys)
		return fmt.Sprintf("%s 取值无效: %q，可用值: %s", field, value, strings.Join(keys, ", "))
	}
	return ""
}
