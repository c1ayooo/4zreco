package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// ── 合成滑块图（与上游 slider_test 同款思路：平滑背景 + 内容匹配） ──────────

func captchaSmoothImage(w, h int, seed int64) *image.RGBA {
	const cell = 8
	rng := rand.New(rand.NewSource(seed))
	gw, gh := w/cell+2, h/cell+2
	grid := make([]float64, gw*gh)
	for i := range grid {
		grid[i] = 28 + rng.Float64()*200
	}
	at := func(x, y int) float64 { return grid[y*gw+x] }
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		fy := float64(y) / cell
		y0 := int(fy)
		ty := fy - float64(y0)
		for x := 0; x < w; x++ {
			fx := float64(x) / cell
			x0 := int(fx)
			tx := fx - float64(x0)
			top := at(x0, y0)*(1-tx) + at(x0+1, y0)*tx
			bottom := at(x0, y0+1)*(1-tx) + at(x0+1, y0+1)*tx
			v := uint8(math.Round(top*(1-ty) + bottom*ty))
			img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
		}
	}
	return img
}

func captchaPNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	return buf.Bytes()
}

// captchaFixture 造一对图：拼图是从背景里裁出的一块（内容匹配型验证码）。
func captchaFixture(t *testing.T, dir string) (bgPNG, piecePNG []byte, tx int) {
	t.Helper()
	bg := captchaSmoothImage(200, 100, 11)
	const pw = 30
	tx, ty := 77, 21
	piece := image.NewRGBA(image.Rect(0, 0, pw, pw))
	draw.Draw(piece, piece.Bounds(), bg, image.Pt(tx, ty), draw.Src)
	bgPNG, piecePNG = captchaPNG(t, bg), captchaPNG(t, piece)
	if dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "bg.png"), bgPNG, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "piece.png"), piecePNG, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return bgPNG, piecePNG, tx
}

func callSolveCaptcha(t *testing.T, ts *ToolSet, body string) (string, bool) {
	t.Helper()
	res, err := ts.solveSliderCaptcha().Call(context.Background(), json.RawMessage(body), nil)
	if err != nil {
		t.Fatalf("工具返回 Go error: %v", err)
	}
	return res.Flatten(), res.IsError
}

func TestSolveSliderCaptchaPathMode(t *testing.T) {
	dir := t.TempDir()
	_, _, wantX := captchaFixture(t, dir)
	out, isErr := callSolveCaptcha(t, &ToolSet{runDir: dir},
		`{"background":"bg.png","piece":"piece.png","initial_x":20,"with_track":true}`)
	if isErr {
		t.Fatalf("路径模式不应失败: %s", out)
	}
	for _, want := range []string{`"background_source":"bg.png"`, `"piece_source":"piece.png"`, `"track":[`} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺 %s：%s", want, out)
		}
	}
	// 解出的 offset 与裁剪位置应接近（算法容差 2px）；distance 另行断言存在即可。
	if !strings.Contains(out, `"offset":`) || !strings.Contains(out, `"distance":`) {
		t.Errorf("缺少 offset/distance：%s", out)
	}
	var parsed struct {
		Offset   int `json:"offset"`
		Distance int `json:"distance"`
		Track    []struct {
			X int `json:"x"`
			T int `json:"t"`
		} `json:"track"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("输出不是合法 JSON: %v (%s)", err, out)
	}
	if d := parsed.Offset - wantX; d > 2 || d < -2 {
		t.Errorf("offset=%d，期望 %d（±2px），算法定位不准", parsed.Offset, wantX)
	}
	if parsed.Distance != parsed.Offset-20 {
		t.Errorf("distance=%d，应为 offset-initial_x=%d", parsed.Distance, parsed.Offset-20)
	}
	if len(parsed.Track) < 2 || parsed.Track[len(parsed.Track)-1].T <= 0 {
		t.Errorf("轨迹不合法: %+v", parsed.Track)
	}
}

func TestSolveSliderCaptchaDataURLMode(t *testing.T) {
	bgPNG, piecePNG, _ := captchaFixture(t, "")
	bgURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(bgPNG)
	pieceB64 := base64.StdEncoding.EncodeToString(piecePNG)
	out, isErr := callSolveCaptcha(t, &ToolSet{}, `{"background":`+jsonQuote(bgURL)+`,"piece":`+jsonQuote(pieceB64)+`}`)
	if isErr {
		t.Fatalf("data URL / base64 模式不应失败: %s", out)
	}
	if !strings.Contains(out, `"background_source":"data-url"`) || !strings.Contains(out, `"piece_source":"base64"`) {
		t.Errorf("来源标记不符：%s", out)
	}
}

func TestSolveSliderCaptchaPathBoundaries(t *testing.T) {
	dir := t.TempDir()
	captchaFixture(t, dir)
	secret := filepath.Join(filepath.Dir(dir), "secret.png")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })

	ts := &ToolSet{runDir: dir}
	cases := map[string]string{
		"相对穿越": `{"background":"../secret.png","piece":"piece.png"}`,
		"绝对树外": `{"background":` + jsonQuote(secret) + `,"piece":"piece.png"}`,
		"非图片":  `{"background":"bg.png","piece":"piece.txt"}`,
		"缺文件":  `{"background":"nope.png","piece":"piece.png"}`,
	}
	// 先放入一个非图片文件，验证扩展名白名单
	if err := os.WriteFile(filepath.Join(dir, "piece.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range cases {
		if out, isErr := callSolveCaptcha(t, ts, body); !isErr {
			t.Errorf("%s 应被拒绝，实际返回：%s", name, out)
		}
	}

	// 没有工作目录时不能用路径模式
	if out, isErr := callSolveCaptcha(t, &ToolSet{}, `{"background":"bg.png","piece":"piece.png"}`); !isErr || !strings.Contains(out, "工作目录") {
		t.Errorf("无 runDir 应报错，得到 isErr=%v out=%s", isErr, out)
	}
}

func TestSolveSliderCaptchaRegistered(t *testing.T) {
	const key = "solve_slider_captcha"
	ts := NewToolSet(nil, "")
	has := func(tools []actool.CoreTool) bool {
		for _, tl := range tools {
			if tl.Name() == key {
				return true
			}
		}
		return false
	}
	if !has(ts.PlannerTools()) || !has(ts.WorkerTools()) || !has(ts.MainAgentTools()) {
		t.Error("solve_slider_captcha 未进入三张工具清单")
	}
	bound := map[string]bool{}
	for _, s := range BuiltinToolSeeds() {
		if s.Key == key {
			for _, a := range s.Agents {
				bound[a] = true
			}
		}
	}
	for _, want := range []string{"planner", "worker", "mainagent"} {
		if !bound[want] {
			t.Errorf("内置工具目录未绑定到 %s", want)
		}
	}
}
