"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

// 认证页防指纹约定（公网部署场景）：
//   1. 本页文案与结构不出现产品名、不引用 /logo.png（图片哈希是最容易被
//      测绘的指纹）；顶部的几何标记是内联 SVG，随主题变化、无独立资源。
//   2. 布局采用居中单卡片形态，与常见开源后台的「左色块 + 右表单」模板区分。
//   3. 合规声明保留（使用条款不因防指纹而省略），但压缩为中性表述。
export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  // 滚动到条款底部（含无需滚动即可完整展示的情况）方可点击「同意」。
  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    // 打开时重置，并处理内容本就不足一屏、无法触发滚动的场景。
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    // 已登录直接进主界面（静态导出下无 middleware 代劳这层跳转）。
    const token = auth.getToken();
    if (token) {
      // localStorage 可能仍有凭据但 cookie 已丢失。先同步，再发起全新请求，
      // 避免服务端守卫或路由缓存把跳转送回仍处于 checking 状态的登录页。
      auth.setToken(token);
      window.location.replace("/function/tasks");
      return;
    }
    api
      .authStatus()
      .then(({ initialized }) => {
        if (!initialized) router.replace("/setup");
      })
      .catch(() => setError("无法连接到后端服务"))
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("请先阅读并同意《安全与合规声明》");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.login("4ZRECO", password);
      auth.setToken(token);
      window.location.replace("/function/tasks");
    } catch (e) {
      // 分型展示：网络断、限流锁定、未初始化、密码错是四种完全不同的用户动作
      // （查网络 / 等待 / 去 /setup / 重输），一律报"密码错误"会诱导用户反复试
      // 密码（越试越锁）。api 层把服务端 error 文本与 HTTP status 挂在 Error 上。
      const err = e as Error & { status?: number };
      if (!err.status) {
        setError("无法连接到后端服务，请确认服务已启动");
      } else if (err.status === 429) {
        setError(err.message || "尝试过于频繁，账号已临时锁定，请稍后再试");
      } else if (err.status === 403 && err.message.includes("未初始化")) {
        setError("密码尚未初始化，请先完成首次设置");
      } else if (err.status === 401) {
        setError("用户名或密码错误");
      } else {
        setError(err.message || "登录失败，请稍后再试");
      }
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        正在检查登录状态…
      </div>
    );
  }

  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden bg-muted/40 p-6">
      {/* 背景几何装饰：细网格 + 顶部光晕，纯 CSS，不引入图片资源。 */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(to right, hsl(var(--border)) 1px, transparent 1px), linear-gradient(to bottom, hsl(var(--border)) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
          maskImage: "radial-gradient(ellipse 70% 60% at 50% 0%, black 30%, transparent 75%)",
          WebkitMaskImage: "radial-gradient(ellipse 70% 60% at 50% 0%, black 30%, transparent 75%)",
        }}
      />

      <div className="relative w-full max-w-sm">
        <div className="rounded-2xl border bg-card p-8 shadow-lg">
          {/* 顶部标记：内联几何图形，替代可哈希指纹的图片 logo。 */}
          <div className="mb-8 flex flex-col items-center gap-3 text-center">
            <svg
              aria-hidden
              viewBox="0 0 48 48"
              className="size-12 text-primary"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="9" y="20" width="30" height="22" rx="4" />
              <path d="M17 20v-6a7 7 0 0 1 14 0v6" />
              <circle cx="24" cy="31" r="2.5" fill="currentColor" stroke="none" />
            </svg>
            <div>
              <h1 className="font-semibold text-xl tracking-tight">控制台登录</h1>
              <p className="mt-1 text-muted-foreground text-sm">仅限授权运维人员访问</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-5">
            <div className="space-y-1.5">
              <Label htmlFor="username">用户名</Label>
              <Input id="username" value="4ZRECO" readOnly className="bg-muted text-muted-foreground" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">密码</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoFocus
                autoComplete="current-password"
              />
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="agree-terms"
                checked={agreed}
                onCheckedChange={(v) => setAgreed(v === true)}
                className="mt-0.5"
              />
              <Label htmlFor="agree-terms" className="font-normal text-muted-foreground text-sm leading-relaxed">
                我已阅读并同意
                <button
                  type="button"
                  onClick={() => setTermsOpen(true)}
                  className="mx-0.5 font-medium text-primary underline-offset-4 hover:underline"
                >
                  《安全与合规声明》
                </button>
              </Label>
            </div>
            {error && <p className="text-destructive text-sm">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading || !password || !agreed}>
              {loading ? "登录中..." : "登录"}
            </Button>
          </form>
        </div>

        <p className="mt-6 text-center text-muted-foreground text-xs">
          连续登录失败会触发临时锁定，请稍后再试
        </p>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
              <AlertTriangle className="size-5" />
            </div>
            <DialogTitle className="text-base">安全与合规声明</DialogTitle>
          </DialogHeader>

          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[55vh] space-y-4 overflow-y-auto px-6 py-5 text-muted-foreground text-sm leading-relaxed"
          >
            <p>
              本系统仅供授权人员在合法授权范围内开展安全评估工作。登录即表示您确认已理解并接受以下约束：
            </p>
            <ul className="ml-5 list-disc space-y-2">
              <li>
                仅可对**已获得明确书面授权**的目标开展测试；对任何未授权系统发起扫描、探测或利用均属违规乃至违法行为；
              </li>
              <li>
                本系统具备在服务器上执行命令的能力——请妥善保管访问凭据，凭据泄露等同于服务器控制权泄露；
              </li>
              <li>
                系统内置拦截与审批机制用于降低误操作风险，但不构成对使用合法性的担保；使用产生的全部法律责任由使用者自行承担；
              </li>
              <li>严禁利用本系统从事任何违反所在国家或地区法律法规的活动。</li>
            </ul>
          </div>

          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-muted-foreground text-xs">
              {readToEnd ? "您已浏览全部条款" : "请将条款滚动至底部后再确认"}
            </p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                我已阅读并同意
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
