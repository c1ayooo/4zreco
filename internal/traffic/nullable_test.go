package traffic

import (
	"context"
	"testing"
)

// U8：exchanges 业务列全部可空（建表无 NOT NULL）。历史库/异常写入留下 NULL 时，
// 直接 Scan 进 string/int 会报 "converting NULL to string is unsupported"，
// 一条脏行就能让整页流量查询失败。这里插一条全 NULL 行，验证所有读路径都兜住。
func TestNullableExchangesColumnsDoNotBreakQueries(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id) VALUES('nullrow')`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`INSERT INTO exchange_bodies(id, req_head, resp_head) VALUES('nullrow','','')`); err != nil {
		t.Fatal(err)
	}

	// 列表/检索
	metas, err := tr.Search("", 0, 10)
	if err != nil {
		t.Fatalf("Search 在可空列下失败: %v", err)
	}
	if len(metas) != 1 || metas[0].ID != "nullrow" {
		t.Fatalf("Search 结果不符: %+v", metas)
	}
	if metas[0].Host != "" || metas[0].Method != "" || metas[0].URLTemplate != "" {
		t.Errorf("NULL 文本列应兜底为空串: %+v", metas[0])
	}

	// 分页查询
	if _, _, err := tr.Page(PageQuery{}, 0, 10); err != nil {
		t.Fatalf("Page 在可空列下失败: %v", err)
	}

	// 主机列表（host 与 MAX(ts) 都可空）
	hosts, err := tr.Hosts()
	if err != nil {
		t.Fatalf("Hosts 在可空列下失败: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Host != "" || hosts[0].Count != 1 {
		t.Fatalf("Hosts 结果不符: %+v", hosts)
	}

	// 证据读取（ts/url/method/status/content_type/req_len/resp_len/path 全 NULL）
	if err := tr.ReadEvidence(context.Background(), []string{"nullrow"}, func(EvidenceExchange) error { return nil }); err != nil {
		t.Fatalf("ReadEvidence 在可空列下失败: %v", err)
	}

	// 归档导出（按 host 选行，同样扫可空列）
	if _, err := tr.ExportHosts([]string{""}, t.TempDir()); err != nil {
		t.Fatalf("ExportHosts 在可空列下失败: %v", err)
	}
}
