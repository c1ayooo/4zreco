package intercept

// incomplete_policy_test.go — B1「不完整脚本快照强制转人工」的策略与端到端测试：
//   - applyIncompleteScriptPolicy 纯函数表驱动（无 DSN 也跑；注意逐字移植的
//     判定条件是 policy != "model"——未知策略一律按 ask 收紧，调用侧永远经
//     getSettingChoice 归一到 ask|model）；
//   - judge 全链路（无 DSN 也跑）：Bash 命令触发 judge → Decision.ModelInput
//     含脚本快照与 SHA-256 / incomplete 状态（默认 "model" 策略不升格）；
//   - settings 键 llm_judge_incomplete_script_action 的取值解析与 "ask" 升格
//     端到端（PG 门控：本仓库唯一存储是 PG，ARTEX 的 sqlite 内存库不可用，
//     与 db/hitl_test.go 同款门控）。

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreco/internal/db"
)

func TestApplyIncompleteScriptPolicy(t *testing.T) {
	cases := []struct {
		name        string
		capture     string
		policy      string
		action      string
		wantAction  string
		wantMessage string
	}{
		{"incomplete_ask_policy_upgrades_allow", "incomplete", "ask", "allow", "ask", "脚本未能完整附加，无法排除隐藏副作用，需要人工确认"},
		{"incomplete_model_policy_keeps_allow", "incomplete", "model", "allow", "allow", ""},
		{"complete_snapshot_never_upgrades", "complete", "ask", "allow", "allow", ""},
		{"not_applicable_never_upgrades", "not_applicable", "ask", "allow", "allow", ""},
		{"incomplete_ask_policy_keeps_deny", "incomplete", "ask", "deny", "deny", ""},
		{"incomplete_ask_policy_keeps_ask", "incomplete", "ask", "ask", "ask", ""},
		{"unknown_policy_fails_closed_to_ask", "incomplete", "", "allow", "ask", "脚本未能完整附加，无法排除隐藏副作用，需要人工确认"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ReviewInput{ScriptCaptureStatus: tc.capture}
			out := applyIncompleteScriptPolicy(in, Decision{Action: tc.action}, tc.policy)
			if out.Action != tc.wantAction {
				t.Fatalf("action=%q want=%q", out.Action, tc.wantAction)
			}
			if out.Message != tc.wantMessage {
				t.Fatalf("message=%q want=%q", out.Message, tc.wantMessage)
			}
		})
	}
}

// judgeScriptFixture 建一个临时目录与一个待执行脚本，返回 (目录, 脚本相对命令, SHA-256)。
func judgeScriptFixture(t *testing.T) (dir, command, sha string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "probe.py"), []byte("print('probe')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("print('probe')\n"))
	return dir, "python3 ./probe.py", fmt.Sprintf("%x", sum)
}

func TestJudgeAttachesScriptSnapshotToModelInput(t *testing.T) {
	dir, command, sha := judgeScriptFixture(t)
	ic := New(nil) // 无 db：judgeConfig 走默认值（IncompleteScriptAction="model"）
	ic.SetReviewer(func(_ context.Context, _ int64, _ string, input ReviewInput) (Decision, error) {
		if len(input.Scripts) != 1 || input.Scripts[0].SHA256 != sha || !input.Scripts[0].Complete || input.ScriptCaptureStatus != "complete" {
			t.Errorf("reviewer received wrong snapshot: status=%q scripts=%+v", input.ScriptCaptureStatus, input.Scripts)
		}
		return Decision{Action: "allow"}, nil
	})
	args, _ := json.Marshal(map[string]string{"command": command})
	// 规则转研判（JudgeRule）不依赖 llm_judge_enabled，可直接验证全链路。
	dec, ok := ic.JudgeRule(WithReviewWorkingDirectory(t.Context(), dir), "Bash", args)
	if !ok {
		t.Fatal("judge not wired")
	}
	if dec.Action != "allow" {
		t.Fatalf("complete snapshot was upgraded despite default model policy: %+v", dec)
	}
	if !strings.Contains(string(dec.ModelInput), `"sha256":"`+sha+`"`) || !strings.Contains(string(dec.ModelInput), `"script_capture_status":"complete"`) {
		t.Fatalf("model input lost the snapshot: %s", dec.ModelInput)
	}
	if dec.ModelInputDigest == "" {
		t.Fatal("model input digest missing")
	}
}

func TestJudgeDefaultPolicyKeepsIncompleteSnapshotWithModel(t *testing.T) {
	dir := t.TempDir()
	ic := New(nil)
	ic.SetReviewer(func(_ context.Context, _ int64, _ string, input ReviewInput) (Decision, error) {
		if input.ScriptCaptureStatus != "incomplete" || len(input.Scripts) != 1 || input.Scripts[0].ReadError == "" {
			t.Errorf("expected incomplete capture, got: status=%q scripts=%+v", input.ScriptCaptureStatus, input.Scripts)
		}
		return Decision{Action: "allow"}, nil
	})
	args, _ := json.Marshal(map[string]string{"command": "python3 ./absent.py"})
	dec, ok := ic.JudgeRule(WithReviewWorkingDirectory(t.Context(), dir), "Bash", args)
	if !ok || dec.Action != "allow" {
		t.Fatalf("default model policy must keep the verdict: ok=%v dec=%+v", ok, dec)
	}
	if !strings.Contains(string(dec.ModelInput), `"script_capture_status":"incomplete"`) {
		t.Fatalf("model input lost the incomplete status: %s", dec.ModelInput)
	}
}

func incompletePolicyTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires ZRECO_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, settingJudgeIncompleteScript)
	})
	return d
}

// 移植自 ARTEX 0.3.29 TestIncompleteScriptConfigDefaultsToModel（sqlite → PG 门控）。
func TestIncompleteScriptConfigDefaultsToModel(t *testing.T) {
	d := incompletePolicyTestDB(t)
	if err := d.SetSetting(settingJudgeIncompleteScript, "noise"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "invalid", "ask", "model"} {
		if value != "" {
			if err := d.SetSetting(settingJudgeIncompleteScript, value); err != nil {
				t.Fatal(err)
			}
		} else if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, settingJudgeIncompleteScript); err != nil {
			t.Fatal(err)
		}
		want := "model"
		if value == "ask" {
			want = "ask"
		}
		if cfg := New(d).GetJudgeConfig(); cfg.IncompleteScriptAction != want {
			t.Fatalf("setting=%q config=%+v", value, cfg)
		}
	}
}

// 端到端（PG 门控）：llm_judge_incomplete_script_action=ask 时，模型判 allow 且
// 快照 incomplete → Decision 升格 ask；快照 complete → 保持 allow。
func TestJudgeIncompleteSnapshotForcedAskEndToEnd(t *testing.T) {
	d := incompletePolicyTestDB(t)
	if err := d.SetSetting(settingJudgeIncompleteScript, "ask"); err != nil {
		t.Fatal(err)
	}
	ic := New(d)
	ic.SetReviewer(func(_ context.Context, _ int64, _ string, _ ReviewInput) (Decision, error) {
		return Decision{Action: "allow"}, nil
	})
	dir := t.TempDir()
	args, _ := json.Marshal(map[string]string{"command": "python3 ./absent.py"})
	dec, ok := ic.JudgeRule(WithReviewWorkingDirectory(t.Context(), dir), "Bash", args)
	if !ok || dec.Action != "ask" {
		t.Fatalf("incomplete snapshot must be forced to ask: ok=%v dec=%+v", ok, dec)
	}
	if !strings.Contains(dec.Message, "脚本未能完整附加") {
		t.Fatalf("upgrade message missing: %q", dec.Message)
	}
	if !dec.TimeoutEnabled || dec.TimeoutSeconds <= 0 {
		t.Fatalf("upgraded ask lost the human-approval timeout: %+v", dec)
	}
	if !strings.Contains(string(dec.ModelInput), `"script_capture_status":"incomplete"`) {
		t.Fatalf("audit model_input lost the incomplete status: %s", dec.ModelInput)
	}

	// 快照完整时不升格。
	dir, command, _ := judgeScriptFixture(t)
	args, _ = json.Marshal(map[string]string{"command": command})
	dec, ok = ic.JudgeRule(WithReviewWorkingDirectory(t.Context(), dir), "Bash", args)
	if !ok || dec.Action != "allow" {
		t.Fatalf("complete snapshot must stay with the model: ok=%v dec=%+v", ok, dec)
	}
}
