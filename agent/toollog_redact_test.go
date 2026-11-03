package agent

import (
	"strings"
	"testing"
)

// 命令摘要里的凭据必须打码——它们会进 journal（默认所有用户可读、还会被导出）。
func TestRedactSecretsHidesCredentials(t *testing.T) {
	cases := []struct {
		in      string
		leak    string // 不得出现在输出里
		wantHas string // 应当保留的内容
	}{
		{"sshpass -p 'dolphin!@#' ssh root@10.0.0.1", "dolphin!@#", "sshpass"},
		{`sshpass -p "hunter2" ssh user@h`, "hunter2", "sshpass"},
		{"sshpass -p plainpass ssh user@h", "plainpass", "sshpass"},
		{"mysql -uroot -p'S3cret!' -h127.0.0.1", "S3cret!", "-uroot"},
		{"psql postgresql://u:p4ss@host/db", "p4ss", "postgresql://"},
		{"mysql -h127.0.0.1 -uroot -pTr0ub4dor", "Tr0ub4dor", "-uroot"},
		{"psql -h 10.0.0.1 -U postgres -p hunter2 -d app", "hunter2", "-U postgres"},
		{"curl -H 'Authorization: Bearer abc123XYZ' http://x", "abc123XYZ", "Authorization"},
		{"curl -H 'Authorization: Basic dXNlcjpwYXNz' http://x", "dXNlcjpwYXNz", "Authorization"},
		{"--password=sup3rsecret user@host", "sup3rsecret", "--password="},
		{"token: ghp_ABCDEFGHIJKLMNOPQRST", "ghp_ABCDEFGHIJKLMNOPQRST", "token:"},
		{"api_key=ak_live_1234567890", "ak_live_1234567890", "api_key="},
	}
	for _, c := range cases {
		got := redactSecrets(c.in)
		if strings.Contains(got, c.leak) {
			t.Errorf("凭据未脱敏: in=%q got=%q", c.in, got)
		}
		if !strings.Contains(got, c.wantHas) {
			t.Errorf("脱敏把有用信息也打掉了: in=%q got=%q want含 %q", c.in, got, c.wantHas)
		}
	}
}

// 脱敏不能误伤正常参数——端口号、路径、普通 flag 都是有用信息，
// 误伤会让日志失去可读性（那还不如不打码）。
func TestRedactSecretsKeepsBenignArgs(t *testing.T) {
	benign := []string{
		"ssh -p 22 root@10.0.0.1",
		"ssh -p 2222 -o StrictHostKeyChecking=no user@h",
		"nmap -sV -p 80,443,8080 10.0.0.1",
		"curl -s http://example.com/path?a=1&b=2",
		"grep -r 'password' /opt/app/config.yaml",
		"cd /opt/4zreco/data/tasks/3/i653 && ls -la",
		// 裸 -p 在不同命令里含义不同：mkdir/tar 的 -p 是 parents/preserve，
		// 不是口令。通用化会误伤——实测 `mkdir -p /some/dir` 的路径被打成 ***。
		"mkdir -p /opt/4zreco/data/tasks/3/i661 && pwd",
		"tar -p -czf backup.tgz /opt/data",
		"cp -p /etc/hosts /tmp/hosts.bak",
	}
	for _, in := range benign {
		if got := redactSecrets(in); got != in {
			t.Errorf("正常参数被误伤: in=%q got=%q", in, got)
		}
	}
}

// 整条命令摘要走一遍脱敏（cmdHead 是日志实际用的入口）。
func TestCmdHeadRedactsAndTrims(t *testing.T) {
	got := cmdHead("sshpass -p 'topsecret' ssh root@h\n第二条")
	if strings.Contains(got, "topsecret") {
		t.Fatalf("cmdHead 未脱敏: %q", got)
	}
	if strings.Contains(got, "第二条") {
		t.Fatalf("cmdHead 应只取第一行: %q", got)
	}
}
