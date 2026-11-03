"use client";

import * as React from "react";

import {
  ActivityIcon,
  DatabaseIcon,
  FolderGitIcon,
  Loader2Icon,
  PlugZapIcon,
  RefreshCwIcon,
  SaveIcon,
  ShieldAlertIcon,
  SquareIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { VulnIntelStatus } from "@/lib/types";

const SOURCE_LABEL: Record<string, string> = {
  nvd: "NVD(CVE 全量/增量)",
  kev: "CISA KEV(在野利用)",
  poc: "GitHub PoC 聚合",
};

type ProbeRow = {
  source: string;
  target: string;
  ok: boolean;
  status: number;
  latency_ms: number;
  error?: string;
  hint?: string;
};

function fmtTime(v?: string): string {
  if (!v) return "—";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return v;
  return d.toLocaleString();
}

// 系统 → 漏洞情报:同步配置 + 水位 + 故障诊断 + 连通性自检 + 手动同步。
// 原先这页只读,失败原因藏在 badge 的 title 里,也没有任何配置入口——
// 现在配置、诊断、修复动作都在同一页。
export default function VulnintelPage() {
  const [status, setStatus] = React.useState<VulnIntelStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [cancelling, setCancelling] = React.useState(false);
  const [probing, setProbing] = React.useState(false);
  const [probeRows, setProbeRows] = React.useState<ProbeRow[]>([]);

  // 配置草稿：凭据字段留空 = 保持不变（避免清空输入框就丢 key）。
  const [nvdKey, setNvdKey] = React.useState("");
  const [ghToken, setGhToken] = React.useState("");
  const [proxy, setProxy] = React.useState("");
  const [pocEnabled, setPocEnabled] = React.useState(false);
  const [backfillDays, setBackfillDays] = React.useState(0);
  const [maxRuntimeMin, setMaxRuntimeMin] = React.useState(30);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vulnintelStatus()
      .then((s) => {
        setStatus(s);
        setError("");
        const c = s.config;
        if (c) {
          setNvdKey("");
          setGhToken("");
          setProxy(c.proxy ?? "");
          setPocEnabled(!!c.poc_enabled);
          setBackfillDays(c.backfill_days ?? 0);
          setMaxRuntimeMin(c.max_runtime_minutes ?? 30);
        }
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(load, [load]);

  const saveConfig = async () => {
    setSaving(true);
    try {
      await api.vulnintelSaveConfig({
        enabled: status?.enabled,
        nvd_api_key: nvdKey.trim() || undefined,
        github_token: ghToken.trim() || undefined,
        proxy: proxy.trim(),
        poc_enabled: pocEnabled,
        backfill_days: backfillDays,
        max_runtime_minutes: maxRuntimeMin,
      });
      toast.success("配置已保存，下一轮同步生效");
      load();
    } catch (e) {
      toast.error("保存失败: " + e);
    } finally {
      setSaving(false);
    }
  };

  const syncNow = async () => {
    setSyncing(true);
    try {
      await api.vulnintelSyncNow();
      toast.success("已触发同步，稍后刷新查看水位");
    } catch (e) {
      toast.error("触发失败: " + e);
    } finally {
      setSyncing(false);
    }
  };

  // 中断当前同步轮：取消是协作式的，点下后后端杀 NVD/git 子进程，状态经轮询刷新。
  const cancelSync = async () => {
    setCancelling(true);
    try {
      await api.vulnintelSyncCancel();
      toast.success("已发出中断请求，正在收尾");
    } catch (e) {
      toast.error("中断失败: " + e);
    } finally {
      setCancelling(false);
    }
  };

  const probe = async () => {
    setProbing(true);
    try {
      const res = await api.vulnintelProbe();
      setProbeRows(res.results ?? []);
      const bad = (res.results ?? []).filter((r) => !r.ok).length;
      if (bad === 0) toast.success("所有数据源连通正常");
      else toast.warning(`${bad} 个数据源不可用，展开看修复建议`);
    } catch (e) {
      toast.error("检测失败: " + e);
    } finally {
      setProbing(false);
    }
  };

  const toggleEnabled = async (on: boolean) => {
    try {
      await api.vulnintelSaveConfig({ enabled: on });
      toast.success(on ? "已开启同步" : "已关闭同步");
      load();
    } catch (e) {
      toast.error("设置失败: " + e);
    }
  };

  const cfg = status?.config;

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlertIcon className="size-5" />
          <h1 className="text-lg font-semibold">漏洞情报</h1>
          {status && (
            <Badge variant={status.enabled ? "default" : "secondary"}>
              {status.enabled ? "同步开启" : "同步关闭"}
            </Badge>
          )}
          {status?.sync_running && (
            <Badge variant="outline" className="max-w-md">
              <Loader2Icon className="mr-1 size-3 shrink-0 animate-spin" />
              <span className="truncate">
                同步进行中{status.sync_phase ? ` · ${status.sync_phase}` : ""}
              </span>
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={probe} disabled={probing}>
            <PlugZapIcon className={"mr-1 size-4" + (probing ? " animate-pulse" : "")} />
            测试连通性
          </Button>
          {status?.sync_running && (
            <Button
              variant="outline"
              size="sm"
              className="text-destructive"
              onClick={cancelSync}
              disabled={cancelling}
            >
              <SquareIcon className="mr-1 size-4" />
              {cancelling ? "中断中…" : "中断同步"}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={syncNow} disabled={syncing}>
            <RefreshCwIcon className={"mr-1 size-4" + (syncing ? " animate-spin" : "")} />
            立即同步
          </Button>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={"mr-1 size-4" + (loading ? " animate-spin" : "")} />
            刷新
          </Button>
        </div>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {status && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                  <DatabaseIcon className="size-4" /> CVE 记录
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold tabular-nums">{status.counts.cves.toLocaleString()}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">KEV 在野利用</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold tabular-nums text-red-500">{status.counts.kev.toLocaleString()}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">PoC 仓库</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-semibold tabular-nums">{status.counts.pocs.toLocaleString()}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">同步配置</CardTitle>
              <CardDescription className="text-xs">
                凭据只写不读：留空表示保持当前值不变。改完点「保存配置」，下一轮同步生效。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-3">
                <Switch checked={!!status.enabled} onCheckedChange={toggleEnabled} id="vi-enabled" />
                <Label htmlFor="vi-enabled" className="text-sm">
                  开启定时同步
                </Label>
                <span className="text-muted-foreground text-xs">{status.next_tick_hint}</span>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-nvd" className="text-xs">
                    NVD API Key{cfg?.nvd_key_set ? "（已配置）" : "（未配置）"}
                  </Label>
                  <Input
                    id="vi-nvd"
                    type="password"
                    value={nvdKey}
                    onChange={(e) => setNvdKey(e.target.value)}
                    placeholder={cfg?.nvd_key_set ? "••••••••" : "留空 = 匿名（5 次/30 秒）"}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-gh" className="text-xs">
                    GitHub Token{cfg?.github_token_set ? "（已配置）" : "（未配置）"}
                  </Label>
                  <Input
                    id="vi-gh"
                    type="password"
                    value={ghToken}
                    onChange={(e) => setGhToken(e.target.value)}
                    placeholder={cfg?.github_token_set ? "••••••••" : "留空 = 匿名（PoC 聚合会限速）"}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-proxy" className="text-xs">
                    同步专用代理（留空 = 跟随维护代理）
                  </Label>
                  <Input
                    id="vi-proxy"
                    value={proxy}
                    onChange={(e) => setProxy(e.target.value)}
                    placeholder={cfg?.maintenance_proxy || "http://127.0.0.1:7897"}
                  />
                  {cfg?.maintenance_proxy && (
                    <span className="text-muted-foreground text-xs">
                      当前维护代理：{cfg.maintenance_proxy}
                    </span>
                  )}
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-backfill" className="text-xs">
                    首次回填天数（0 = 全量）
                  </Label>
                  <Input
                    id="vi-backfill"
                    type="number"
                    min={0}
                    value={backfillDays}
                    onChange={(e) => setBackfillDays(Math.max(0, Number(e.target.value) || 0))}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="vi-runtime" className="text-xs">
                    单轮上限（分钟）
                  </Label>
                  <Input
                    id="vi-runtime"
                    type="number"
                    min={5}
                    value={maxRuntimeMin}
                    onChange={(e) => setMaxRuntimeMin(Math.max(5, Number(e.target.value) || 5))}
                  />
                </div>
                <div className="flex items-end gap-3">
                  <div className="flex items-center gap-2">
                    <Switch checked={pocEnabled} onCheckedChange={setPocEnabled} id="vi-poc" />
                    <Label htmlFor="vi-poc" className="text-sm">
                      聚合 GitHub PoC 仓库
                    </Label>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <Button size="sm" onClick={saveConfig} disabled={saving}>
                  <SaveIcon className="mr-1 size-4" />
                  保存配置
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">同步状态</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="py-2 pr-4 font-medium">数据源</th>
                      <th className="py-2 pr-4 font-medium">最近同步</th>
                      <th className="py-2 pr-4 font-medium">本轮处理</th>
                      <th className="py-2 pr-4 font-medium">状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.sources.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-3 text-muted-foreground">
                          尚未开始同步（首次启动约 90 秒后开始；全量回填需数轮）
                        </td>
                      </tr>
                    )}
                    {status.sources.map((s) => (
                      <tr key={s.source} className="border-b align-top last:border-0">
                        <td className="py-2 pr-4">{SOURCE_LABEL[s.source] ?? s.source}</td>
                        <td className="py-2 pr-4 tabular-nums">{fmtTime(s.last_sync_at)}</td>
                        <td className="py-2 pr-4 tabular-nums">{s.total_synced.toLocaleString()}</td>
                        <td className="py-2 pr-4">
                          {s.last_error ? (
                            <div className="space-y-1">
                              <Badge variant="destructive" className="gap-1">
                                <TriangleAlertIcon className="size-3" />
                                有错误
                              </Badge>
                              <p className="max-w-xl text-muted-foreground text-xs">{s.last_error}</p>
                              {s.error_hint && (
                                <p className="max-w-xl text-xs text-amber-600 dark:text-amber-400">
                                  建议：{s.error_hint}
                                </p>
                              )}
                            </div>
                          ) : (
                            <Badge variant="default">正常</Badge>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <FolderGitIcon className="size-4" /> nuclei 模板库
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-muted-foreground text-xs">
                目录：{status.nuclei?.dir || status.nuclei_templates_dir || "未配置"}
              </p>
              {status.nuclei && (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="secondary">{status.nuclei.templates} 个模板</Badge>
                    {status.nuclei.is_git && <Badge variant="outline">git 仓库</Badge>}
                    {status.nuclei.updated_at && (
                      <span className="text-muted-foreground text-xs">
                        最近更新 {fmtTime(status.nuclei.updated_at)}
                      </span>
                    )}
                  </div>
                  <p className="text-muted-foreground text-xs">{status.nuclei.hint}</p>
                </>
              )}
            </CardContent>
          </Card>

          {probeRows.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                  <ActivityIcon className="size-4" /> 连通性自检
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="py-2 pr-4 font-medium">数据源</th>
                        <th className="py-2 pr-4 font-medium">结果</th>
                        <th className="py-2 pr-4 font-medium">耗时</th>
                        <th className="py-2 pr-4 font-medium">说明</th>
                      </tr>
                    </thead>
                    <tbody>
                      {probeRows.map((r) => (
                        <tr key={r.source} className="border-b align-top last:border-0">
                          <td className="py-2 pr-4">{SOURCE_LABEL[r.source] ?? r.source}</td>
                          <td className="py-2 pr-4">
                            {r.ok ? (
                              <Badge variant="default">通 {r.status}</Badge>
                            ) : (
                              <Badge variant="destructive">{r.status ? `HTTP ${r.status}` : "失败"}</Badge>
                            )}
                          </td>
                          <td className="py-2 pr-4 tabular-nums">{r.latency_ms} ms</td>
                          <td className="py-2 pr-4 text-xs">
                            {r.error && <p className="text-destructive">{r.error}</p>}
                            {r.hint && <p className="text-amber-600 dark:text-amber-400">{r.hint}</p>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
