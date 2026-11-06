package imhub

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	pgdb "github.com/c1ayooo/4zreco/internal/db"
)

// imhub_test.go — 移植自 4zrec internal/platform/server/im_test.go（帧编解码/
// 企微加解密/telegram 归一化/截断/卡片形状），另加命令路由的表驱动用例。
// 全部纯单测，零 DB 依赖。

func TestImFeishuFrameRoundTrip(t *testing.T) {
	f := &imFeishuFrame{
		SeqID:   42,
		LogID:   7,
		Service: 101,
		Method:  1,
		Headers: []imFeishuHeader{
			{Key: "type", Value: "event"},
			{Key: "message_id", Value: "m-1"},
			{Key: "sum", Value: "1"},
			{Key: "seq", Value: "0"},
		},
		Payload: []byte(`{"schema":"2.0"}`),
	}
	raw := imFeishuFrameEncode(f)
	got, err := imFeishuFrameDecode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SeqID != f.SeqID || got.LogID != f.LogID || got.Service != f.Service || got.Method != f.Method {
		t.Fatalf("字段不回环: %+v vs %+v", got, f)
	}
	if len(got.Headers) != len(f.Headers) {
		t.Fatalf("header 数不一致: %d vs %d", len(got.Headers), len(f.Headers))
	}
	for i, hh := range f.Headers {
		if got.Headers[i] != hh {
			t.Fatalf("header[%d] 不一致: %+v vs %+v", i, got.Headers[i], hh)
		}
	}
	if !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("payload 不一致: %q vs %q", got.Payload, f.Payload)
	}
}

// TestImFeishuFrameWireFormat 用手工按 protobuf wire 规则拼的字节校验编码器的
// 字段号/线型与官方 SDK 的 pbbp2.Frame 定义一致（SeqID=1 varint, LogID=2,
// Service=3, Method=4, Headers=5 rep, Payload=8 bytes）。
func TestImFeishuFrameWireFormat(t *testing.T) {
	f := &imFeishuFrame{SeqID: 1, LogID: 2, Service: 3, Method: 4,
		Headers: []imFeishuHeader{{Key: "k", Value: "v"}},
		Payload: []byte("hello")}
	raw := imFeishuFrameEncode(f)

	var expect bytes.Buffer
	putVarint := func(v uint64) {
		var tmp [binary.MaxVarintLen64]byte
		expect.Write(tmp[:binary.PutUvarint(tmp[:], v)])
	}
	putVarint(1<<3 | 0)
	putVarint(1)
	putVarint(2<<3 | 0)
	putVarint(2)
	putVarint(3<<3 | 0)
	putVarint(3)
	putVarint(4<<3 | 0)
	putVarint(4)
	// Header{Key:1, Value:2} 包装进 field 5
	var hb bytes.Buffer
	writeLenDelim := func(field int, s string) {
		var tmp [binary.MaxVarintLen64]byte
		hb.Write(tmp[:binary.PutUvarint(tmp[:], uint64(field)<<3|2)])
		hb.Write(tmp[:binary.PutUvarint(tmp[:], uint64(len(s)))])
		hb.WriteString(s)
	}
	writeLenDelim(1, "k")
	writeLenDelim(2, "v")
	putVarint(5<<3 | 2)
	putVarint(uint64(hb.Len()))
	expect.Write(hb.Bytes())
	putVarint(8<<3 | 2)
	putVarint(5)
	expect.WriteString("hello")

	if !bytes.Equal(raw, expect.Bytes()) {
		t.Fatalf("wire 格式与预期不一致:\n got %x\nwant %x", raw, expect.Bytes())
	}
}

func TestImFeishuFrameDecodeRejectsGarbage(t *testing.T) {
	if _, err := imFeishuFrameDecode([]byte{0x0f, 0xff, 0xff}); err == nil {
		t.Fatal("垃圾字节应报错")
	}
}

// TestImWecomCryptRoundTrip 自加密→解密回环（加密侧按官方算法镜像实现）。
func TestImWecomCryptRoundTrip(t *testing.T) {
	aesKeyB64 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" // 43 字符
	key, err := base64.StdEncoding.DecodeString(aesKeyB64 + "=")
	if err != nil || len(key) != 32 {
		t.Fatalf("测试用 key 非法: %v", err)
	}
	encrypt := func(plain []byte, receiveID string) string {
		// 官方算法：16B 随机 + 4B 大端长度 + 消息 + receiveID，整体按 32 字节块 PKCS7 填充。
		body := make([]byte, 0, 20+len(plain)+len(receiveID)+32)
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			t.Fatal(err)
		}
		body = append(body, rnd[:]...)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(plain)))
		body = append(body, lenBuf[:]...)
		body = append(body, plain...)
		body = append(body, []byte(receiveID)...)
		pad := 32 - len(body)%32
		for i := 0; i < pad; i++ {
			body = append(body, byte(pad))
		}
		block, _ := aes.NewCipher(key)
		out := make([]byte, len(body))
		cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(out, body)
		return base64.StdEncoding.EncodeToString(out)
	}

	msg := `<xml><FromUserName>zhangsan</FromUserName><MsgType>text</MsgType><Content>/bond</Content><MsgId>123</MsgId></xml>`
	enc := encrypt([]byte(msg), "corp123")
	sig := imWecomSignature("tok", "1700000000", "nonce1", enc)

	plain, err := imWecomDecrypt(aesKeyB64, sig, "tok", "1700000000", "nonce1", enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != msg {
		t.Fatalf("回环不一致:\n got %q\nwant %q", plain, msg)
	}

	// 篡改签名必须拒绝
	if _, err := imWecomDecrypt(aesKeyB64, "badbadbad", "tok", "1700000000", "nonce1", enc); err == nil {
		t.Fatal("错误签名应解密失败")
	}
}

func TestImTelegramNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/bond", "/bond"},
		{"/bond@MyBot", "/bond"},
		{"/bond@MyBot 虎牙", "/bond 虎牙"},
		{"/bond 虎牙", "/bond 虎牙"},
		{"普通消息", "普通消息"},
		{" /new ", "/new"},
	}
	for _, c := range cases {
		if got := imTelegramNormalize(c.in); got != c.want {
			t.Fatalf("imTelegramNormalize(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestImTruncateRunes(t *testing.T) {
	const marker = "\n…（已截断）"
	long := strings.Repeat("测", imTelegramMaxText+10)
	got := imTruncateRunes(long, imTelegramMaxText)
	if len([]rune(got)) != imTelegramMaxText+len([]rune(marker)) {
		t.Fatalf("截断后长度异常: %d", len([]rune(got)))
	}
	if !strings.HasSuffix(got, marker) {
		t.Fatal("缺少截断标记")
	}
	if imTruncateRunes("短文本", 100) != "短文本" {
		t.Fatal("短文本不应被截断")
	}
}

func TestImFeishuCard(t *testing.T) {
	card := imFeishuCard("**绑定**：项目「虎牙src」")
	if card["msg_type"] != nil { // 卡片本身不含 msg_type（外层 body 才有）
		t.Fatal("卡片不应包含 msg_type")
	}
	elems, ok := card["elements"].([]any)
	if !ok || len(elems) != 1 {
		t.Fatalf("elements 异常: %#v", card["elements"])
	}
	div := elems[0].(map[string]any)
	text := div["text"].(map[string]any)
	if text["tag"] != "lark_md" {
		t.Fatalf("lark_md 缺失: %#v", text)
	}
	if !strings.Contains(text["content"].(string), "**绑定**") {
		t.Fatal("markdown 正文丢失")
	}
	// JSON 编码后是合法字符串（IM API 的 content 字段是卡片 JSON 的字符串形态）
	if _, err := json.Marshal(card); err != nil {
		t.Fatalf("卡片 JSON 编码失败: %v", err)
	}
}

// ---- 命令路由（表驱动）----

func TestParseChatCommand(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		name   string
		args   []string
		reason string
	}{
		{"/bond", true, "bond", nil, "无参 bond=查看绑定"},
		{"/bond 虎牙", true, "bond", []string{"虎牙"}, "单参绑定项目"},
		{"/bond 虎牙 任务A", true, "bond", []string{"虎牙", "任务A"}, "双参绑定项目+任务"},
		{"/BOND off", true, "bond", []string{"off"}, "指令名不分大小写"},
		{"/new", true, "new", nil, "轮换新会话"},
		{"/commands", true, "commands", nil, "指令清单"},
		{"/help", true, "help", nil, "同义指令"},
		{"/bondx", true, "", nil, "形似指令的未知纯字母 token 也按已处理"},
		{"/etc/passwd", false, "", nil, "含路径分隔符不是指令"},
		{"/1abc", false, "", nil, "非纯字母 token 不是指令"},
		{"普通消息", false, "", nil, "非 / 开头"},
		{"", false, "", nil, "空消息"},
		{"  /new  ", true, "new", nil, "前后空白容忍"},
	}
	for _, c := range cases {
		cmd, ok := ParseChatCommand(c.in)
		if ok != c.ok {
			t.Fatalf("ParseChatCommand(%q) ok=%v want %v（%s）", c.in, ok, c.ok, c.reason)
		}
		if !ok {
			continue
		}
		if cmd.Name != c.name {
			t.Fatalf("ParseChatCommand(%q) name=%q want %q（%s）", c.in, cmd.Name, c.name, c.reason)
		}
		if strings.Join(cmd.Args, ",") != strings.Join(c.args, ",") {
			t.Fatalf("ParseChatCommand(%q) args=%v want %v（%s）", c.in, cmd.Args, c.args, c.reason)
		}
	}
}

func TestCommandHelpMentionsAllCommands(t *testing.T) {
	help := CommandHelp()
	for _, want := range []string{"/bond", "/new", "/commands"} {
		if !strings.Contains(help, want) {
			t.Fatalf("CommandHelp 缺少 %s：%s", want, help)
		}
	}
}

func TestMatchProjectAndTask(t *testing.T) {
	projects := []pgdb.Project{
		{ID: 1, Name: "虎牙src"},
		{ID: 2, Name: "虎牙移动端"},
		{ID: 3, Name: "其他"},
	}
	if p, _, ok := matchProject(projects, "1"); !ok || p.ID != 1 {
		t.Fatal("按编号应精确命中")
	}
	if p, _, ok := matchProject(projects, "虎牙src"); !ok || p.ID != 1 {
		t.Fatal("精确名应命中")
	}
	if _, amb, ok := matchProject(projects, "虎牙"); ok || len(amb) != 2 {
		t.Fatalf("子串命中多个应返回候选清单: ok=%v amb=%d", ok, len(amb))
	}
	if _, _, ok := matchProject(projects, "不存在"); ok {
		t.Fatal("无命中应返回 false")
	}
	tasks := []*pgdb.Task{
		{ID: 10, Name: "外网侦察", Status: "running"},
		{ID: 11, Name: "口令喷洒", Queued: true},
		{ID: 12, Name: "内网横向", Paused: true},
		{ID: 13, Name: "已完结", Status: "done"},
	}
	if tk, _, ok := matchTask(tasks, "11"); !ok || tk.ID != 11 {
		t.Fatal("任务按编号应命中")
	}
	if tk, _, ok := matchTask(tasks, "外网"); !ok || tk.ID != 10 {
		t.Fatalf("单命中子串应直接返回 match: ok=%v", ok)
	}
	if _, amb, ok := matchTask(tasks, "网"); !ok && len(amb) < 2 {
		t.Fatalf("多命中子串应返回候选清单: ok=%v amb=%d", ok, len(amb))
	}
	if got := taskStatusZH(tasks[1]); got != "排队中" {
		t.Fatalf("Queued 应优先显示排队中: %s", got)
	}
	if got := taskStatusZH(tasks[2]); got != "已暂停" {
		t.Fatalf("Paused 应优先显示已暂停: %s", got)
	}
	if got := taskStatusZH(tasks[3]); got != "已完成" {
		t.Fatalf("done 应显示已完成: %s", got)
	}
}

// TestFormatProjectListShowsConvCount 锁定 4zreco 适配：项目清单展示对话数
// （4zrec 的 AssetCount 在本仓不存在）。
func TestFormatProjectListShowsConvCount(t *testing.T) {
	ps := []pgdb.Project{{ID: 7, Name: "示例项目", TaskCount: 3, ConvCount: 5}}
	got := formatProjectList(ps)
	if !strings.Contains(got, "任务 3") || !strings.Contains(got, "对话 5") {
		t.Fatalf("应展示任务/对话计数: %s", got)
	}
	if strings.Contains(got, "资产") {
		t.Fatalf("4zreco 项目无资产计数，不应出现「资产」: %s", got)
	}
	if formatProjectList(nil) != "（无项目）" {
		t.Fatal("空清单应返回（无项目）")
	}
}
