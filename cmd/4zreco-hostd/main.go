// Command 4zreco-hostd 是 4ZRECO 的特权安装助手。
//
// 它由 systemd 以 root 常驻,只监听一个 Unix socket,按 hosttools 白名单执行
// 「一键安装」。主服务(4zreco)受 NoNewPrivileges + ProtectSystem=strict 限制无法
// 提权,因此安装动作必须落在这里。
//
// 用法:
//
//	4zreco-hostd -socket /run/4zreco/hostd.sock -socket-group 4zreco
//	4zreco-hostd -check          # 自检:包管理器/目录权限/白名单,不启动服务
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/c1ayooo/4zreco/internal/hostd"
	"github.com/c1ayooo/4zreco/internal/hosttools"
)

// version 由构建时 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	var (
		socketPath  = flag.String("socket", "/run/4zreco/hostd.sock", "Unix socket 路径")
		socketMode  = flag.String("socket-mode", "0660", "socket 权限(八进制)")
		socketGroup = flag.String("socket-group", "", "socket 属组(留空=不改,通常填主服务的运行用户)")
		check       = flag.Bool("check", false, "自检后退出(不启动服务)")
		showVer     = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("4zreco-hostd", version)
		return
	}

	mgr := hostd.DetectPkgMgr()
	if *check {
		runCheck(*socketPath, *socketGroup, mgr)
		return
	}

	if os.Geteuid() != 0 {
		log.Fatalf("[hostd] 需要 root 运行(安装动作要写 /usr、调用包管理器)")
	}
	if mgr == hostd.PkgNone {
		log.Printf("[hostd] 警告: 未检测到 apt/dnf,GitHub/pip 类工具仍可安装")
	}

	mode := parseMode(*socketMode)
	ln, err := hostd.Listen(*socketPath, mode, *socketGroup)
	if err != nil {
		log.Fatalf("[hostd] 监听 %s 失败: %v", *socketPath, err)
	}
	log.Printf("[hostd] v%s 就绪 socket=%s mode=%s group=%q pkg_mgr=%s tools=%d",
		version, *socketPath, *socketMode, *socketGroup, mgr, len(hosttools.Inventory()))

	// 任务的父 ctx = 进程生命周期：收到 SIGTERM 时连正在跑的安装一起取消。
	// 绝不能传 HTTP 请求的 ctx——handler 返回即取消，排队任务会当场变 cancelled。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hs := hostd.NewServer(ctx, log.New(os.Stderr, "", log.LstdFlags))
	hs.Version = version
	// 自身路径用于「自我换装」：改了名/软链也认得出真实文件。
	if exe, runErr := os.Executable(); runErr == nil {
		if resolved, e := filepath.EvalSymlinks(exe); e == nil {
			exe = resolved
		}
		hs.SelfPath = exe
	}

	srv := &http.Server{
		Handler:           hs.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[hostd] 服务异常: %v", err)
		}
	}()
	<-ctx.Done()
	log.Printf("[hostd] 收到停止信号,优雅退出")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = os.Remove(*socketPath)
}

// runCheck 不启动服务,只报告环境是否满足安装条件——供部署脚本与排障用。
func runCheck(socketPath, group string, mgr hostd.PkgMgr) {
	fmt.Printf("4zreco-hostd %s\n", version)
	fmt.Printf("euid        : %d (需要 0)\n", os.Geteuid())
	fmt.Printf("pkg_mgr     : %q (apt/dnf 用于系统源工具)\n", string(mgr))
	fmt.Printf("socket      : %s\n", socketPath)
	fmt.Printf("socket_group: %q\n", group)
	if d := dirOf(socketPath); d != "" {
		if err := os.MkdirAll(d, 0o755); err == nil {
			fmt.Printf("socket dir  : %s 可创建 ✓\n", d)
		} else {
			fmt.Printf("socket dir  : %s 创建失败 ✗ %v\n", d, err)
		}
	}
	if _, err := net.ResolveUnixAddr("unix", socketPath); err != nil {
		fmt.Printf("unix socket : 不支持 ✗ %v\n", err)
	}
	inv := hosttools.Inventory()
	miss := 0
	for _, t := range inv {
		if !t.Available {
			miss++
		}
	}
	fmt.Printf("tools       : 可用 %d / %d,缺失 %d(可一键安装 %d)\n",
		len(inv)-miss, len(inv), miss, countInstallable(inv))
}

func countInstallable(inv []hosttools.Tool) int {
	n := 0
	for _, t := range inv {
		if !t.Available && t.Installable {
			n++
		}
	}
	return n
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return ""
}

func parseMode(s string) os.FileMode {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		log.Fatalf("[hostd] socket-mode 需为八进制,收到 %q", s)
	}
	return os.FileMode(v)
}
