"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  ClipboardPasteIcon,
  FlaskConicalIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  Trash2Icon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ProxyPoolEntry, ProxyPoolRunning } from "@/lib/types";

const STRATEGY_LABEL: Record<string, string> = {
  round_robin: "轮询(按权重)",
  sticky_host: "按目标粘性(同目标固定出口)",
  sticky_host_random: "按目标粘性(首次随机)",
  random: "随机",
};

type CheckRow = {
  index: number;
  url: string;
  ok: boolean;
  latency_ms: number;
  exit_ip?: string;
  error?: string;
  checked_at: string;
};

// 系统 → 代理池:多上游出口配置(轮换/粘性/随机),条目启停与权重。
// 保存即热应用(upstream 钩子按请求选代理);连败 5 次自动熔断 10 分钟,
// 另有主动健康检查定时验证、不通即熔断。
export default function ProxyPoolPage() {
  const [entries, setEntries] = React.useState<ProxyPoolEntry[]>([]);
  const [strategy, setStrategy] = React.useState("round_robin");
  const [running, setRunning] = React.useState<ProxyPoolRunning[]>([]);
  const [capturing, setCapturing] = React.useState(false);
  const [checkTarget, setCheckTarget] = React.useState("");
  const [healthMinutes, setHealthMinutes] = React.useState(10);
  const [lastCheck, setLastCheck] = React.useState<{
    at: string;
    target: string;
    count: number;
    ok_count: number;
    auto?: boolean;
  } | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [checking, setChecking] = React.useState(false);
  const [checkRows, setCheckRows] = React.useState<CheckRow[]>([]);
  const [bulkOpen, setBulkOpen] = React.useState(false);
  const [bulkText, setBulkText] = React.useState("");
  const [bulkMode, setBulkMode] = React.useState<"append" | "replace">("append");

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .proxyPoolGet()
      .then((r) => {
        setEntries(r.entries ?? []);
        setStrategy(r.strategy || "round_robin");
        setRunning(r.running ?? []);
        setCapturing(r.capturing);
        setCheckTarget(r.check_target ?? "");
        setHealthMinutes(r.health_minutes ?? 10);
        setLastCheck(r.last_check ?? null);
      })
      .catch((e) => toast.error("加载失败: " + e))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(load, [load]);

  const save = async () => {
    setSaving(true);
    try {
      await api.proxyPoolPut({ entries, strategy });
      toast.success("代理池已保存并热应用");
      load();
    } catch (e) {
      toast.error("保存失败: " + e);
    } finally {
      setSaving(false);
    }
  };

  const update = (i: number, patch: Partial<ProxyPoolEntry>) => {
    setEntries((prev) => prev.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  };

  const failuresByURL = React.useMemo(() => {
    const m: Record<string, ProxyPoolRunning> = {};
    for (const r of running) m[r.url] = r;
    return m;
  }, [running]);

  // 失效 = 熔断中（被动连败或主动健康检查判定不通）。
  const deadURLs = React.useMemo(
    () => new Set(running.filter((r) => (r.break_remaining ?? 0) > 0).map((r) => r.url)),
    [running],
  );

  const runCheck = async (urls?: string[]) => {
    setChecking(true);
    try {
      const res = await api.proxyPoolCheck({
        urls,
        target: checkTarget || undefined,
        break_on_fail: true,
      });
      setCheckRows(res.results ?? []);
      const ok = (res.results ?? []).filter((r) => r.ok).length;
      const total = (res.results ?? []).length;
      if (total === 0) {
        toast.warning("没有可验证的条目（池为空或已全部停用）");
      } else {
        toast.success(`验证完成：${ok}/${total} 可用，不通的已熔断`);
      }
      load();
    } catch (e) {
      toast.error("验证失败: " + e);
    } finally {
      setChecking(false);
    }
  };

  const doBulk = async () => {
    try {
      const res = await api.proxyPoolBulk({ text: bulkText, mode: bulkMode });
      const bad = res.invalid?.length ?? 0;
      toast.success(`导入完成：新增 ${res.added}、更新 ${res.updated}` + (bad ? `，${bad} 行无效` : ""));
      setBulkOpen(false);
      setBulkText("");
      load();
    } catch (e) {
      toast.error("导入失败: " + e);
    }
  };

  const removeDead = () => {
    if (deadURLs.size === 0) {
      toast.info("没有失效条目");
      return;
    }
    setEntries((prev) => prev.filter((e) => !deadURLs.has(e.url)));
    toast.success(`已移除 ${deadURLs.size} 个失效条目，记得点「保存并热应用」`);
  };

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h1 className="font-semibold text-2xl tracking-tight">代理池</h1>
          <Badge variant={entries.length > 0 ? "default" : "secondary"}>
            {entries.length > 0 ? `${entries.length} 个上游` : "未启用(直连/全局代理)"}
          </Badge>
          {deadURLs.size > 0 && <Badge variant="destructive">{deadURLs.size} 个不可用</Badge>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Dialog open={bulkOpen} onOpenChange={setBulkOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <ClipboardPasteIcon className="mr-1 size-4" />
                批量导入
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-2xl">
              <DialogHeader>
                <DialogTitle>批量导入代理</DialogTitle>
                <DialogDescription>
                  一行一个。自动识别 <code>1.2.3.4:8080</code>、<code>http://…</code>、<code>socks5://user:pass@…</code>
                  、<code>1.2.3.4:8080:user:pass</code>；<code>#</code> 开头是注释；
                  <code>名字 | 地址</code> 可指定名称。省略协议按 http 处理。
                </DialogDescription>
              </DialogHeader>
              <Textarea
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                rows={12}
                className="font-mono text-xs"
                placeholder={
                  "# 名称 | 地址\nHK-01 | 1.2.3.4:8080\nsocks5://user:pass@5.6.7.8:1080\n10.0.0.1:3128:user:pass"
                }
              />
              <div className="flex items-center gap-3">
                <Label className="text-xs">导入方式</Label>
                <Select value={bulkMode} onValueChange={(v) => setBulkMode(v as "append" | "replace")}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="append">追加到现有列表</SelectItem>
                    <SelectItem value="replace">替换整个列表</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button variant="outline" size="sm" onClick={() => setBulkOpen(false)}>
                  取消
                </Button>
                <Button size="sm" onClick={doBulk} disabled={!bulkText.trim()}>
                  导入
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={"mr-1 size-4" + (loading ? " animate-spin" : "")} />
            刷新
          </Button>
          <Button size="sm" onClick={save} disabled={saving}>
            <SaveIcon className="mr-1 size-4" />
            保存并热应用
          </Button>
        </div>
      </div>

      {!capturing && (
        <Alert className="border-warning/40 bg-warning/10 text-warning">
          <AlertDescription className="text-warning">
            流量捕获未开启时代理池不生效（worker 流量需经捕获代理 :8788 才走出口轮换）
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">轮换策略</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Select value={strategy} onValueChange={setStrategy}>
            <SelectTrigger className="w-72">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="round_robin">轮询(按权重)</SelectItem>
              <SelectItem value="sticky_host">按目标粘性(同目标固定出口)</SelectItem>
              <SelectItem value="sticky_host_random">按目标粘性(首次随机选定)</SelectItem>
              <SelectItem value="random">随机</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            连败 5 次自动熔断 10 分钟;池非空时优先于「全局出口代理」。 「首次随机」=
            同一目标第一次随机选一个出口并固定，该出口挂掉后自动换。
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">健康检查与验证</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="check-target" className="text-xs">
                探测地址
              </Label>
              <Input
                id="check-target"
                className="w-72"
                value={checkTarget}
                onChange={(e) => setCheckTarget(e.target.value)}
                placeholder="https://api.ipify.org?format=json"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="health-min" className="text-xs">
                自动检查间隔（分钟，0=关闭）
              </Label>
              <Input
                id="health-min"
                type="number"
                min={0}
                className="w-32"
                value={healthMinutes}
                onChange={(e) => setHealthMinutes(Math.max(0, Number(e.target.value) || 0))}
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => runCheck()} disabled={checking}>
              <FlaskConicalIcon className={"mr-1 size-4" + (checking ? " animate-spin" : "")} />
              验证全部
            </Button>
            {deadURLs.size > 0 && (
              <Button variant="outline" size="sm" onClick={removeDead}>
                <Trash2Icon className="mr-1 size-4" />
                移除失效条目
              </Button>
            )}
          </div>
          {lastCheck && (
            <p className="text-xs text-muted-foreground">
              最近检查：{new Date(lastCheck.at).toLocaleString()} · {lastCheck.ok_count}/{lastCheck.count} 可用
              {lastCheck.auto ? "（自动巡检）" : ""} · 探测 {lastCheck.target}
            </p>
          )}
          {checkRows.length > 0 && (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>出口</TableHead>
                    <TableHead>结果</TableHead>
                    <TableHead className="hidden sm:table-cell">耗时</TableHead>
                    <TableHead className="hidden md:table-cell">出口 IP</TableHead>
                    <TableHead className="hidden lg:table-cell">错误</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {checkRows.map((r) => (
                    <TableRow key={r.url}>
                      <TableCell className="font-mono text-xs">{r.url}</TableCell>
                      <TableCell>
                        {r.ok ? (
                          <span className="inline-flex items-center gap-1 text-success">
                            <CheckCircle2Icon className="size-4" /> 可用
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-destructive">
                            <XCircleIcon className="size-4" /> 不可用
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="hidden tabular-nums sm:table-cell">{r.latency_ms} ms</TableCell>
                      <TableCell className="hidden font-mono text-xs md:table-cell">{r.exit_ip ?? "—"}</TableCell>
                      <TableCell className="hidden text-destructive text-xs lg:table-cell">{r.error ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2 flex-row flex items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">上游代理</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setEntries((p) => [...p, { url: "", name: "", enabled: true, weight: 1 }])}
          >
            <PlusIcon className="mr-1 size-4" />
            添加
          </Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {entries.length === 0 && (
            <p className="py-3 text-sm text-muted-foreground">
              暂无条目。用「批量导入」一次贴入整份代理列表，或点「添加」逐条录入 （http/https/socks5，支持 user:pass）。
            </p>
          )}
          {entries.map((e, i) => {
            const live = failuresByURL[e.url];
            const dead = deadURLs.has(e.url);
            return (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <Input
                  className="flex-1 font-mono text-xs"
                  placeholder="socks5://user:pass@1.2.3.4:1080"
                  value={e.url}
                  onChange={(ev) => update(i, { url: ev.target.value })}
                />
                <Input
                  className="w-36"
                  placeholder="名称(可选)"
                  value={e.name}
                  onChange={(ev) => update(i, { name: ev.target.value })}
                />
                <div className="flex items-center gap-1">
                  <span className="text-xs text-muted-foreground">权重</span>
                  <Input
                    className="w-16"
                    type="number"
                    min={1}
                    value={e.weight}
                    onChange={(ev) => update(i, { weight: Math.max(1, Number(ev.target.value) || 1) })}
                  />
                </div>
                <Switch
                  checked={e.enabled}
                  aria-label={`启用 ${e.name || e.url || `条目 ${i + 1}`}`}
                  onCheckedChange={(v) => update(i, { enabled: v })}
                />
                {dead && (
                  <Badge variant="destructive" title={live?.last_fail}>
                    <AlertTriangleIcon className="mr-1 size-3" />
                    熔断 {live?.break_remaining}s
                  </Badge>
                )}
                {!dead && live && live.failures > 0 && <Badge variant="destructive">连败 {live.failures}</Badge>}
                {!dead && live?.last_ok && (
                  <Badge variant="secondary" title={`最近成功 ${live.last_ok}`}>
                    可用
                  </Badge>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`删除 ${e.name || e.url || `条目 ${i + 1}`}`}
                  onClick={() => setEntries((p) => p.filter((_, j) => j !== i))}
                >
                  <Trash2Icon className="size-4" />
                </Button>
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
