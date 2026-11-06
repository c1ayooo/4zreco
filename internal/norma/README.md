# internal/norma — 类型基座（norma v0.4.4 fork，冻结）

P4（eino 迁移收尾）引入：norma SDK 退出 go.mod 后，仓库仍在使用的**类型与运行时
基座**按 v0.4.4 非测试代码逐字 fork 到此（Apache-2.0，见 [LICENSE](LICENSE)；
上游 norma 仓库与维护者 fork 均为原作者/社区资产，版权归其作者所有）。

## 包清单与现状

| 包 | 内容 | 现状 |
|---|---|---|
| `llm` | DTO（Message/ContentBlock/StreamEvent…）、Provider 接口与三家 HTTP provider、Accumulator、boundary | 活代码：落盘 JSON 形状冻结的唯一权威（llmrec 录制/replay、transcript、acllm 转换层都靠它） |
| `tool` | CoreTool/BaseTool/ToolContext 框架 + SDK 内置工具（Bash/Read/Write/Edit/Grep/WebFetch/Todo/Task/PTY shell…） | 活代码：agent 工具面基座 |
| `permission` | Decision/Context/Mode | 活代码：guard/内核权限类型 |
| `transcript` | Store/Writer/Record | 活代码：落盘 transcript |
| `harness` | Event/Terminal/Query 类型词汇表 | 类型为主：eino 内核保留其终态/事件词汇（termmap/askernel） |
| `skill` | Registry/LoadDir | 活代码：skill 加载 |
| `hook` | Registry | 活代码：guard 的 HTTP hook 面 |
| `mcp` | stdio MCP 客户端 | 活代码：MCP 发现 |

未 fork（随 P4 一并退役）：`agentcore`/`noaadapter`（运行时已被 eino 内核替代；
noa 实验功能退化为告警+内置 compaction 回退，见 `internal/agent/noa.go`）、
`compaction`（已移植进 `internal/acllm`，差分 golden 见 `internal/acllm/testdata/compaction_port/`）、
`memory`/`plan`/`noa`/`coordinator`/`subagent`（无引用）。

## 规则

- **冻结**：此目录只收上游代码的逐字拷贝（含其注释与风格），不做风格化改写、
  不加新功能；唯一的机械改动是 import 路径（模块路径 → 本仓库 internal 路径）。
  要改行为，先确认改的是不是应该改 eino 侧/acllm 侧。
- fork 不带上游测试（部分上游测试依赖未 fork 的 agentcore 生态）；本仓库
  `internal/acllm`、`internal/llmrec`、`internal/agent` 的测试覆盖其行为面。
- 升级 eino / 改 DTO 字段时，落盘 JSON 形状（llm.Message 等）不变仍是硬约束。

## fork 内偏差登记（改行为前已确认无法在 eino/acllm 侧修复）

- `llm/openai_responses.go` / `llm/openai.go`（2026-11-06）：并行工具调用修复。
  上游 v0.4.4 的 Responses 适配器给所有工具事件发零值 ToolIndex、Chat Completions
  适配器给 tool_input 事件漏带 index，多个并行 function_call 经 acllm.BridgeModel
  落到同一 eino Index 上，`schema.ConcatMessages` 报 "cannot concat ToolCalls with
  different tool id"（DeepSeek 实测触发）。桥侧无法区分（ToolIndex==0 与"未设"不可
  分辨），故在 provider 源头锚定：Responses 按 output_index/item_id，Chat
  Completions 按tool_calls[].index。回归测试 `internal/acllm/parallel_tool_stream_test.go`。
  仅新增运行时事件字段取值，落盘 DTO JSON 形状不变。
