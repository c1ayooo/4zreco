package agent

// 任务级后台作业（v0.4.64 批次，移植自上游 tools_jobs.go，含 0.4.71/0.4.80 的
// #18 配套修复：jobLifecycleMu 生命周期锁 + PID 归属校验 + 收尸）：job_start /
// job_status / job_output / job_stop。
//
// ## 为什么需要它
//
// 「跑到一半就没了」的深挖，根因之一是单意图墙钟：长扫描、爆破、多步利用链必须
// 在一个意图里跑完，超时即被判死；下一个意图从零开始重做。Bash 的后台能力绑在
// 单次 run 的会话里，run 结束进程就没人管，也没有跨意图的「作业台账」。
//
// 本组工具把作业落到 tasks/<id>/shared/jobs/：
//   - <name>.sh    作业脚本（末尾回写退出码）
//   - <name>.log   stdout+stderr
//   - <name>.json  元数据（pid/命令/启动时间/发起意图）
//
// 于是：worker A 起一个长爆破 → run 结束也不影响进程 → 后续任意意图用 job_status/
// job_output 取结果；planner 也可以轮询作业而不是反复派新意图。
//
// ## 管控
//
// job_start 等价于 Bash（执行任意命令）；日志与脚本都在任务目录内，受同一套
// 审计留痕。任务暂停/删除时由 KillJobsForTaskDir 收尸（server 侧接线）。

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// jobLifecycleMu 串行化「作业启动+登记」与「暂停/删除清理」。
//
// job_start 从开始启动到元数据落盘必须持读锁；KillJobsForTaskDir 持写锁。
// 没有这把锁时，清理会扫描不到「进程已启动、JSON 还没写」的作业，暂停后它
// 继续在后台打目标（上游 issue #18）。锁是进程内全局的：job 启停频率很低，
// 没必要为每个任务目录维护一张锁表。
var jobLifecycleMu sync.RWMutex

// jobStartAfterStartHook 仅测试使用：进程已启动、元数据尚未落盘。生产恒为 nil。
var jobStartAfterStartHook func()

type jobMeta struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	PID     int    `json:"pid"`
	Started string `json:"started"`
	Script  string `json:"script"`
	Log     string `json:"log"`
	RCFile  string `json:"rc_file"`
	Intent  int64  `json:"intent_id,omitempty"`
}

func (t *ToolSet) jobsDir() string {
	dir := t.sharedDir()
	if dir == "" {
		return ""
	}
	j := filepath.Join(dir, "jobs")
	if err := os.MkdirAll(j, 0o755); err != nil {
		return ""
	}
	return j
}

func sanitizeJobName(name string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return -1
	}, strings.TrimSpace(name))
	if clean == "" || len(clean) > 64 {
		return ""
	}
	return clean
}

func readJobMeta(dir, name string) (jobMeta, bool) {
	var m jobMeta
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil {
		return m, false
	}
	return m, true
}

// jobState 返回 (状态, 退出码)。状态：running|finished|failed|unknown。
func jobState(m jobMeta) (string, int) {
	if b, err := os.ReadFile(m.RCFile); err == nil {
		code := -1
		// echo > rc 是「先创建/截断再写入」：轮询可能正好读到空文件。解析不出数字
		// 时不能当成 failed（会把刚跑完的作业误报失败），退回进程存活判定。
		if n, _ := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &code); n == 1 {
			if code == 0 {
				return "finished", 0
			}
			return "failed", code
		}
	}
	if m.PID > 0 {
		// 刚启动的包装进程可能还没完成 exec，/proc cmdline 仍是父进程的；
		// 5s 启动窗口内不做归属校验，避免把新作业误判成 PID 复用。
		startedAt, startErr := time.Parse(time.RFC3339, m.Started)
		inStartup := startErr == nil && time.Since(startedAt) < 5*time.Second
		if !inStartup && !jobOwnsProcess(m) {
			// PID 已被系统复用：元数据是上一次运行的残留，不能当成 running，
			// 更不能在任务暂停/删除时按这个 PID 杀进程组。
			return "failed", -1
		}
		if alive, known := jobProcessAlive(m.PID); known && !alive {
			// Windows 上「进程退出」与「rc 文件可见」之间有短暂窗口：刚结束的
			// 作业不能立刻报 failed。启动 5s 内按 running 处理，之后才认定崩溃。
			if started, err := time.Parse(time.RFC3339, m.Started); err == nil && time.Since(started) < 5*time.Second {
				return "running", -1
			}
			return "failed", -1 // 进程已退出但没留下 rc（崩溃/被外部杀）
		}
		return "running", -1
	}
	return "unknown", -1
}

func (t *ToolSet) jobStart() actool.CoreTool {
	return writeTool(
		"job_start",
		"在任务级后台启动一个长任务（长扫描/爆破/监听/多步利用），run 结束后进程继续运行，"+
			"后续任意意图或 planner 都能用 job_status/job_output 取结果。\n"+
			"作业落在 tasks/<id>/shared/jobs/：脚本、日志、退出码。适合超过单意图预算的动作；"+
			"一次性的短命令仍用 Bash。\n"+
			"注意：启动后不要立刻反复 job_output 空转——先去做别的，隔一段时间或换意图再看。",
		obj(map[string]any{
			"name":    str("作业名（字母数字-_，同名会覆盖旧作业）"),
			"command": str("要执行的 bash 命令（工作目录为任务 shared 目录）"),
			"env":     str("额外环境变量，'K=V&K2=V2'（可选）"),
		}, "name", "command"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name    string `json:"name"`
				Command string `json:"command"`
				Env     string `json:"env"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeJobName(a.Name)
			if name == "" || name != strings.TrimSpace(a.Name) {
				return actool.Errorf("name 非法：只允许字母/数字/-/_（不能含路径分隔符或点）"), nil
			}
			if strings.TrimSpace(a.Command) == "" {
				return actool.Errorf("command 不能为空"), nil
			}
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（本次 run 没有注入工作目录）"), nil
			}
			// 暂停/删除清理（KillJobsForTaskDir）持写锁。这里把「启动 + 元数据落盘」
			// 整体放进读锁：清理要么在启动前完成（随后 ctx 检查拒绝），要么等登记
			// 完成后再扫到并杀掉，不会漏掉中途启动的作业（上游 issue #18）。
			jobLifecycleMu.RLock()
			defer jobLifecycleMu.RUnlock()
			if err := ctx.Err(); err != nil {
				return actool.Errorf("任务已暂停或执行已取消，拒绝启动后台作业"), nil
			}
			script := filepath.Join(dir, name+".sh")
			logPath := filepath.Join(dir, name+".log")
			rcPath := filepath.Join(dir, name+".rc")
			metaPath := filepath.Join(dir, name+".json")
			_ = os.Remove(rcPath)
			// Git Bash（开发机）对反斜杠路径不友好；脚本内统一用正斜杠。
			scriptEnv := filepath.ToSlash(script)
			rcEnv := filepath.ToSlash(rcPath)
			workEnv := filepath.ToSlash(filepath.Dir(dir))
			body := "#!/usr/bin/env bash\nset -uo pipefail\ncd " + shellQuote(workEnv) + "\n" +
				a.Command + "\nrc=$?\necho $rc > " + shellQuote(rcEnv) + "\nexit $rc\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				return actool.Errorf("写作业脚本失败: " + err.Error()), nil
			}
			logEnv := filepath.ToSlash(logPath)
			// 头部单独写；子进程用 shell 重定向写日志（不依赖父进程持有句柄，
			// Windows 上父进程关闭句柄会让子进程后续写入静默失败）。
			if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				fmt.Fprintf(lf, "\n=== job %s start %s ===\n", name, time.Now().Format(time.RFC3339))
				_ = lf.Close()
			}
			// 同名作业重跑：先停掉仍在跑的旧进程组，避免两份扫描同时打目标。
			if old, ok := readJobMeta(dir, name); ok {
				if st, _ := jobState(old); st == "running" {
					_ = jobKillGroup(old.PID)
					jobWaitGone(old.PID, 2*time.Second)
				}
			}
			cmd := exec.Command(resolveBash(), "-c",
				`bash "$0" >> "$2" 2>&1; rc=$?; echo $rc > "$1"; exit $rc`,
				scriptEnv, rcEnv, logEnv)
			cmd.Dir = filepath.Dir(dir)
			// 独立进程组：job_stop 杀整组，内层脚本/子进程一起结束（不再只杀外层包装 shell）。
			cmd.SysProcAttr = jobSysProcAttr()
			env := os.Environ()
			for _, kv := range strings.Split(a.Env, "&") {
				k, v, ok := strings.Cut(kv, "=")
				if ok && strings.TrimSpace(k) != "" {
					env = append(env, strings.TrimSpace(k)+"="+v)
				}
			}
			cmd.Env = env
			if err := ctx.Err(); err != nil {
				return actool.Errorf("任务已暂停或执行已取消，拒绝启动后台作业"), nil
			}
			if err := cmd.Start(); err != nil {
				return actool.Errorf("启动作业失败: " + err.Error()), nil
			}
			if jobStartAfterStartHook != nil {
				jobStartAfterStartHook()
			}
			pid := cmd.Process.Pid
			// 作业跨 run 存活：用后台 Wait 收尸，不能 Release——Release 不回收子进程，
			// 每个作业会留一个僵尸，长期运行把容器 pids limit 占满（此后所有 exec 都失败）。
			go func() { _ = cmd.Wait() }()
			m := jobMeta{
				Name: name, Command: a.Command, PID: pid,
				Started: time.Now().Format(time.RFC3339),
				Script:  script, Log: logPath, RCFile: rcPath,
				Intent: t.ownerNode,
			}
			b, err := json.MarshalIndent(m, "", "  ")
			if err == nil {
				err = os.WriteFile(metaPath, b, 0o644)
			}
			if err != nil {
				// 元数据写不进去 = 这个进程永远不在作业台账里，暂停/删除都找不到它。
				// 立刻杀掉整组，不能留一个不可追踪的后台进程。
				_ = jobKillGroup(pid)
				jobWaitGone(pid, 2*time.Second)
				return actool.Errorf("写作业元数据失败（已终止进程）: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"name":   name,
				"pid":    pid,
				"log":    logPath,
				"script": script,
				"note":   "作业已在后台运行。用 job_status/job_output 查看；不要立刻反复轮询，先做别的工作。",
			})
		},
	)
}

// shellQuote 把字符串包成 POSIX sh 单引号字面量（作业脚本/命令组命令共用）。
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// resolveBash 选择可用的 bash。Windows 上 PATH 里常先命中 System32\bash.exe
// （WSL 启动器，看不到 C:/ 本地路径），优先用 Git for Windows 的 bash。
func resolveBash() string {
	if runtime.GOOS == "windows" {
		for _, p := range []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
		} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "bash"
}

func (t *ToolSet) jobStatus() actool.CoreTool {
	return readTool(
		"job_status",
		"查看后台作业状态（running/finished/failed + 退出码 + 日志尾部）。不传 name 列出全部作业；"+
			"传 name 看单个作业的最近输出。",
		obj(map[string]any{
			"name":       str("作业名（可选；省略=列出全部）"),
			"tail_lines": intp("单作业时返回的日志尾部行数，默认 40，最大 400"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name      string `json:"name"`
				TailLines int    `json:"tail_lines"`
			}
			_ = json.Unmarshal(in, &a)
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（本次 run 没有注入工作目录）"), nil
			}
			if strings.TrimSpace(a.Name) != "" {
				name := sanitizeJobName(a.Name)
				if name == "" {
					return actool.Errorf("name 非法"), nil
				}
				m, ok := readJobMeta(dir, name)
				if !ok {
					return actool.Errorf("作业不存在: " + name), nil
				}
				state, code := jobState(m)
				tail := a.TailLines
				if tail <= 0 {
					tail = 40
				}
				if tail > 400 {
					tail = 400
				}
				out := map[string]any{
					"name": name, "state": state, "exit_code": code,
					"pid": m.PID, "started": m.Started, "log": m.Log,
					"tail": tailLines(m.Log, tail),
				}
				if st, err := os.Stat(m.Log); err == nil {
					out["log_bytes"] = st.Size()
				}
				return jsonResult(out)
			}
			// 列全部
			entries, _ := os.ReadDir(dir)
			jobs := []map[string]any{}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				name := strings.TrimSuffix(e.Name(), ".json")
				m, ok := readJobMeta(dir, name)
				if !ok {
					continue
				}
				state, code := jobState(m)
				item := map[string]any{"name": name, "state": state, "exit_code": code, "started": m.Started}
				if st, err := os.Stat(m.Log); err == nil {
					item["log_bytes"] = st.Size()
					item["log_mtime"] = st.ModTime().Format(time.RFC3339)
				}
				jobs = append(jobs, item)
			}
			return jsonResult(map[string]any{"count": len(jobs), "jobs": jobs,
				"note": "running 的作业跨意图存活；failed 看 job_output 定位原因。"})
		},
	)
}

// jobLogLineMax 单行保留上限。长扫描可能吐出超长单行（进度条 / base64），
// 整行读进内存会把进程拖垮；超长部分截断并标记。
const jobLogLineMax = 4 << 10

// readLogLine 读一行，超过 jobLogLineMax 的尾部丢弃（IO 仍消费完，行号才不会错）。
func readLogLine(r *bufio.Reader) (string, bool, error) {
	var sb strings.Builder
	truncated := false
	for {
		frag, err := r.ReadSlice('\n')
		if sb.Len() < jobLogLineMax {
			room := jobLogLineMax - sb.Len()
			if len(frag) > room {
				sb.Write(frag[:room])
				truncated = true
			} else {
				sb.Write(frag)
			}
		} else if len(frag) > 0 {
			truncated = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		line := strings.TrimRight(sb.String(), "\r\n")
		if truncated {
			line += " …(行超长已截断)"
		}
		if err == io.EOF {
			if line == "" {
				return "", false, io.EOF
			}
			return line, true, nil
		}
		if err != nil {
			return line, line != "", err
		}
		return line, true, nil
	}
}

// readJobLog 返回日志的 [offset, offset+limit) 行窗口与总行数。
//
// offset == 0 表示「读尾部 limit 行」：用环形缓冲只保留最后 limit 行，
// 内存不随日志大小增长（整份读入的旧实现，几 GB 的扫描日志会直接 OOM）。
func readJobLog(path string, offset, limit int) (window []string, total int, err error) {
	if limit <= 0 {
		limit = 1 // 环形缓冲要取模，0 会 panic
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	if offset <= 0 {
		ring := make([]string, limit)
		filled, pos := 0, 0
		for {
			line, ok, rerr := readLogLine(r)
			if ok {
				ring[pos] = line
				pos = (pos + 1) % limit
				if filled < limit {
					filled++
				}
				total++
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return nil, total, rerr
			}
		}
		out := make([]string, 0, filled)
		for i := 0; i < filled; i++ {
			out = append(out, ring[(pos-filled+i+limit)%limit])
		}
		return out, total, nil
	}
	for {
		line, ok, rerr := readLogLine(r)
		if ok {
			if total >= offset && len(window) < limit {
				window = append(window, line)
			}
			total++
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return window, total, rerr
		}
	}
	return window, total, nil
}

func tailLines(path string, n int) string {
	lines, _, err := readJobLog(path, 0, n)
	if err != nil {
		return ""
	}
	return strings.Join(lines, "\n")
}

func (t *ToolSet) jobOutput() actool.CoreTool {
	return readTool(
		"job_output",
		"读后台作业日志（默认尾部 200 行）。日志很大时用 offset/lines 翻页；完整日志本身就在"+
			"tasks/<id>/shared/jobs/<name>.log，可用 Bash grep。",
		obj(map[string]any{
			"name":   str("作业名"),
			"lines":  intp("返回行数，默认 200，最大 1000"),
			"offset": intp("起始行号（0 基），用于翻页；省略=读尾部"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name   string `json:"name"`
				Lines  int    `json:"lines"`
				Offset int    `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeJobName(a.Name)
			if name == "" {
				return actool.Errorf("name 非法"), nil
			}
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（本次 run 没有注入工作目录）"), nil
			}
			m, ok := readJobMeta(dir, name)
			if !ok {
				return actool.Errorf("作业不存在: " + name), nil
			}
			lines := a.Lines
			if lines <= 0 {
				lines = 200
			}
			if lines > 1000 {
				lines = 1000
			}
			start := a.Offset
			if start < 0 {
				start = 0
			}
			window, total, err := readJobLog(m.Log, start, lines)
			if err != nil {
				return actool.Errorf("读取日志失败: " + err.Error()), nil
			}
			from := start
			if start == 0 && len(window) < total {
				from = total - len(window) // offset=0 是「读尾部」，起始行按实际窗口回推
			}
			if from > total {
				from = total
			}
			end := from + len(window)
			state, code := jobState(m)
			res := map[string]any{
				"name": name, "state": state, "exit_code": code,
				"total_lines": total, "from_line": from, "to_line": end,
				"output": strings.Join(window, "\n"),
			}
			if end < total {
				res["next_offset"] = end
			}
			return jsonResult(res)
		})
}

func (t *ToolSet) jobStop() actool.CoreTool {
	return writeTool(
		"job_stop",
		"停止一个后台作业（SIGKILL），并回读退出码。作业已完成时是 no-op。",
		obj(map[string]any{
			"name": str("作业名"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			name := sanitizeJobName(a.Name)
			if name == "" {
				return actool.Errorf("name 非法"), nil
			}
			dir := t.jobsDir()
			if dir == "" {
				return actool.Errorf("任务共享目录不可用（本次 run 没有注入工作目录）"), nil
			}
			m, ok := readJobMeta(dir, name)
			if !ok {
				return actool.Errorf("作业不存在: " + name), nil
			}
			state, code := jobState(m)
			stopped := false
			if state == "running" && m.PID > 0 {
				if err := jobKillGroup(m.PID); err == nil {
					stopped = true
					// SIGKILL 是异步的：等进程真正退出再返回，否则调用方（测试/暂停/删除
					// 清理）紧接着检查进程状态会看到残留而误判「没杀掉」。
					jobWaitGone(m.PID, 2*time.Second)
					// 外层包装进程一起被杀，rc 不会再写；补一个 137（SIGKILL）标记，
					// 否则 jobState 会因 PID>0 永远显示 running。
					_ = os.WriteFile(m.RCFile, []byte("137"), 0o644)
					code = 137
				}
			}
			return jsonResult(map[string]any{
				"name": name, "stopped": stopped, "state_before": state, "exit_code": code,
				"note": "停止的是整个进程组（脚本及其子进程）。",
			})
		},
	)
}
