package agent

// kernelrun_test.go 的装配辅助：actool.CoreTool 别名与一个最小探针工具。

import (
	"context"
	"encoding/json"
	"testing"

	acperm "github.com/c1ayooo/4zreco/internal/norma/permission"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

type coreToolAlias = actool.CoreTool

func mustProbeTool(t *testing.T) actool.CoreTool {
	t.Helper()
	return actool.Build(actool.Spec{
		Name:        "probe",
		Description: "probe",
		Schema:      map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("probe ran"), nil
		},
	})
}
