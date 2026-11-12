"use client";

import * as React from "react";

import { ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";

// 可选 HTTP Basic Auth 访问门设置卡（ARTEX 移植 A4）。门在 JWT 之外再拦一层：
// 启用后所有页面与 API 先过 Basic 挑战。口令留空=不改；每次保存轮换 revision，
// 旧门会话全部失效。
export function BasicAuthCard() {
  const [enabled, setEnabled] = React.useState(false);
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [passwordSet, setPasswordSet] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");

  const load = React.useCallback(async () => {
    setError("");
    try {
      const settings = await api.basicAuthSettings();
      setEnabled(settings.enabled);
      setUsername(settings.username);
      setPasswordSet(settings.password_set);
      setLoaded(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "读取失败");
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const settings = await api.setBasicAuthSettings({ enabled, username: username.trim(), password });
      setEnabled(settings.enabled);
      setUsername(settings.username);
      setPasswordSet(settings.password_set);
      setPassword("");
      toast.success(settings.enabled ? "HTTP Basic Auth 已启用" : "HTTP Basic Auth 已停用");
    } catch (e) {
      setError(e instanceof Error ? e.message : "保存失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <ShieldCheckIcon className="size-4" />
          HTTP Basic Auth
        </CardTitle>
        <CardDescription>为整站再加一层访问口令：启用后先过 Basic 验证，再走平台登录。</CardDescription>
      </CardHeader>
      <form onSubmit={save}>
        <CardContent className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="basic-auth-enabled" className="font-normal text-muted-foreground text-sm">
              {enabled ? "已启用 · 访问需先过 Basic 验证" : "已关闭 · 仅平台登录"}
            </Label>
            <Switch
              id="basic-auth-enabled"
              checked={enabled}
              onCheckedChange={setEnabled}
              disabled={!loaded || saving}
            />
          </div>
          <Label htmlFor="basic-auth-username" className="font-normal text-muted-foreground text-sm">
            用户名
          </Label>
          <Input
            id="basic-auth-username"
            autoComplete="off"
            value={username}
            required={enabled}
            disabled={!loaded || saving}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="入口用户名（不含冒号）"
          />
          <Label htmlFor="basic-auth-password" className="font-normal text-muted-foreground text-sm">
            口令
          </Label>
          <Input
            id="basic-auth-password"
            type="password"
            autoComplete="new-password"
            value={password}
            required={enabled && !passwordSet}
            disabled={!loaded || saving}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={passwordSet ? "留空=不修改" : "至少 8 位"}
          />
          <p className="text-muted-foreground text-xs">保存后所有已通过验证的会话立即失效，需重新输入。</p>
          {error ? (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          ) : null}
          <div className="mt-2 flex items-center gap-2">
            <Button type="submit" disabled={!loaded || saving}>
              {saving ? "保存中…" : "保存"}
            </Button>
            {!loaded && error ? (
              <Button type="button" variant="outline" onClick={load}>
                重试
              </Button>
            ) : null}
          </div>
        </CardContent>
      </form>
    </Card>
  );
}
