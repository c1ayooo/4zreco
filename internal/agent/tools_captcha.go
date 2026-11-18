package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/4zreco/internal/captcha"
	actool "github.com/c1ayooo/4zreco/internal/norma/tool"
)

// captchaMaxFileBytes 是单张图片的读取上限。滑块验证码的两张图正常 <200KB，
// 8MB 足够覆盖整页截图，同时挡住「误传大文件」把 worker 卡住。
const captchaMaxFileBytes = 8 << 20

// captchaImageExts 是允许的图片扩展名白名单（文件路径模式下校验）。
var captchaImageExts = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true}

// solveSliderCaptcha 用纯图像算法求解滑块验证码（第三批 J3，移植自 Jingwei
// v1.6.5 `captcha`）。
//
// 为什么要它：滑块是登录/注册/找回密码链路上最常见的机器人校验，手工估缺口位置
// 既费时又容易连续失败把账号锁掉。这里直接给出缺口坐标与拟人拖动轨迹，worker 拿到
// 后用 http_request / session_login 提交即可——**不启动浏览器、不发任何请求**。
//
// 输入边界：图片可以是任务目录内路径（相对 runDir 或目录内绝对路径，PNG/JPEG/GIF，
// 单文件 ≤8MB），也可以是 data URL / 裸 base64。路径两侧 EvalSymlinks + 前缀校验，
// 翻不出任务目录。
func (t *ToolSet) solveSliderCaptcha() actool.CoreTool {
	return readTool(
		"solve_slider_captcha",
		"求解滑块验证码：给背景图与拼图，返回缺口 offset/distance/y 与置信度，可选附拟人拖动轨迹（x/y/t 毫秒序列）。"+
			"纯图像算法，不启动浏览器、不发请求——拿到结果后用 http_request / session_login 提交。"+
			"图片可以是本意图工作目录内的文件路径（相对路径或目录内绝对路径，PNG/JPEG/GIF，≤8MB），"+
			"也可以是 data URL 或裸 base64。带 initial_x（拼图在界面上的可见左边界）时 distance=offset-initial_x。"+
			"连续失败两次就别再猜：换人工核对或换登录路径，避免触发账号锁定。",
		obj(map[string]any{
			"background": str("背景图：任务目录内路径，或 data URL / 裸 base64"),
			"piece":      str("拼图：任务目录内路径，或 data URL / 裸 base64"),
			"initial_x":  intp("拼图在验证码界面中的可见左边界（可选；给了则返回 distance）"),
			"min_offset": intp("缺口搜索下界（可选，像素）"),
			"max_offset": intp("缺口搜索上界（可选，像素）"),
			"with_track": boolp("是否附带拟人拖动轨迹（x/y/t 毫秒序列，默认 false）"),
			"seed":       intp("轨迹随机种子（可选；同种子可复现同一条轨迹）"),
		}, "background", "piece"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Background string `json:"background"`
				Piece      string `json:"piece"`
				InitialX   int    `json:"initial_x"`
				MinOffset  int    `json:"min_offset"`
				MaxOffset  int    `json:"max_offset"`
				WithTrack  bool   `json:"with_track"`
				Seed       int64  `json:"seed"`
			}
			_ = json.Unmarshal(in, &a)

			bg, bgSrc, err := captchaImageBytes(t.runDir, a.Background)
			if err != nil {
				return actool.Errorf("background: " + err.Error()), nil
			}
			piece, pieceSrc, err := captchaImageBytes(t.runDir, a.Piece)
			if err != nil {
				return actool.Errorf("piece: " + err.Error()), nil
			}
			res, err := captcha.SolveSlider(bg, piece, captcha.SolveOptions{
				InitialX:  a.InitialX,
				MinOffset: a.MinOffset,
				MaxOffset: a.MaxOffset,
			})
			if err != nil {
				return actool.Errorf("求解失败: " + err.Error()), nil
			}
			out := map[string]any{
				"background_source": bgSrc,
				"piece_source":      pieceSrc,
				"offset":            res.Offset,
				"distance":          res.Distance,
				"y":                 res.Y,
				"confidence":        res.Confidence,
				"score":             res.Score,
				"background_size":   []int{res.BackgroundWidth, res.BackgroundHeight},
				"piece_size":        []int{res.PieceWidth, res.PieceHeight},
				"elapsed_ms":        res.ElapsedMS,
				"note": "offset 是缺口在背景图坐标系里的横坐标；网页要拖动的距离通常还要减去拼图初始左边界" +
					"（传 initial_x 可直接拿 distance）。提交后核对响应，别在同一会话反复重试。",
			}
			if a.WithTrack {
				out["track"] = captcha.HumanTrack(res.Distance, captcha.TrackOptions{Seed: a.Seed})
			}
			return jsonResult(out)
		},
	)
}

// captchaImageBytes 解析图片入参：data URL / 裸 base64 直接解码；带图片扩展名的
// 当任务目录内文件路径读取（限界 + 大小上限）。
func captchaImageBytes(runDir, raw string) ([]byte, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", errors.New("图片不能为空")
	}
	// base64 会膨胀约 4/3：先按 2 倍上限挡掉超大输入，避免解码前就吃掉内存。
	if len(raw) > captchaMaxFileBytes*2 {
		return nil, "", fmt.Errorf("输入过大（%d 字节），单张图片上限 %d", len(raw), captchaMaxFileBytes)
	}
	if strings.HasPrefix(strings.ToLower(raw), "data:") {
		b, err := captcha.DecodeDataURL(raw)
		if err != nil {
			return nil, "", err
		}
		return b, "data-url", nil
	}
	switch strings.ToLower(filepath.Ext(raw)) {
	case ".png", ".jpg", ".jpeg", ".gif":
		data, rel, err := readWorkspaceFile(runDir, raw, captchaImageExts, captchaMaxFileBytes)
		if err != nil {
			return nil, "", err
		}
		return data, rel, nil
	}
	b, err := captcha.DecodeDataURL(raw)
	if err != nil {
		return nil, "", errors.New("既不是任务目录内的图片路径（.png/.jpg/.jpeg/.gif），也不是合法的 base64 / data URL")
	}
	return b, "base64", nil
}
