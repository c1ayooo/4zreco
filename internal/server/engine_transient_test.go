package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// v0.4.27：worker run 内部的 context canceled（provider 流取消等）不算终局失败，
// 与 model_error 同待遇进退避重试；任务级取消不算（由既有分支处理）。
func TestIsTransientContextCanceled(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"wrapped canceled", fmt.Errorf("stream: %w", context.Canceled), true},
		{"text match", errors.New("error: context canceled"), true},
		{"other", errors.New("connection reset by peer"), false},
		{"deadline is not cancel", fmt.Errorf("run: %w", context.DeadlineExceeded), false},
	}
	for _, c := range cases {
		if got := isTransientContextCanceled(c.err); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
