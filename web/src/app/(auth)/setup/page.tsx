"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function SetupPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  // 查不到初始化状态时不能默认当成"未初始化"——那样会把初始化表单摆给一个
  // 其实已经设过密码的实例，用户照着填就会覆盖掉原密码。此时关闭入口。
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then(({ initialized }) => {
        if (initialized) router.replace("/login");
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "无法连接到后端服务");
        setUnavailable(true);
      })
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("两次输入的密码不一致");
      return;
    }
    if (password.length < 8) {
      setError("密码长度至少 8 位");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.initPassword(password);
      auth.setToken(token);
      router.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : "初始化失败");
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    // 骨架高度对齐下方真实卡片（标题 + 双字段表单）。
    return (
      <div className="flex min-h-dvh items-center justify-center bg-muted/40 p-6">
        <Skeleton className="h-96 w-full max-w-sm rounded-2xl" />
      </div>
    );
  }

  return (
    <div className="flex min-h-dvh items-center justify-center bg-muted/40 p-6">
      {/* 与登录页同形态：居中单卡片，不带任何可哈希的图片资源 */}
      <div className="w-full max-w-sm">
        <div className="space-y-10 rounded-2xl border bg-card p-8 shadow-lg lg:p-10">
          <h1 className="text-center font-semibold text-2xl tracking-tight">
            {unavailable ? "无法确认初始化状态" : "初始化密码"}
          </h1>
          {unavailable ? (
            <div className="flex flex-col gap-4">
              <Alert variant="destructive">
                <AlertTriangle />
                <AlertDescription>
                  后端或数据库暂时不可用。为避免覆盖实例上已有的密码，初始化入口已临时关闭——请恢复服务后重试。
                  {error ? `（${error}）` : ""}
                </AlertDescription>
              </Alert>
              <Button type="button" className="w-full" onClick={() => window.location.reload()}>
                重试
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="password">新密码</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="至少 8 位"
                  autoFocus
                  autoComplete="new-password"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">确认密码</Label>
                <Input
                  id="confirm"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="再次输入密码"
                  autoComplete="new-password"
                />
              </div>
              {error && <p className="text-destructive text-sm">{error}</p>}
              <Button type="submit" className="w-full" disabled={loading || !password || !confirm}>
                {loading ? "保存中..." : "设置密码并登录"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
