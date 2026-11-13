"use client";
import * as React from "react";

import Link from "next/link";

import { CopyIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { StatusBadge, ToneDot } from "@/components/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { IntelligenceKind, IntelligencePage, TaskIntelligence } from "@/lib/types";
import { copyText } from "@/lib/utils";

// 任务情报面板（C2，移植自 ARTEX 0.3.29）。三类 tab + 搜索 + 状态筛选 + 详情弹层 +
// 人工定级；任务/资产两个维度共用（scope 区分）。凭据验证 agent 的派生展示属后续
// 单独工单，这里只展示原始情报行（原始情报始终是权威数据）。

const KINDS: { value: IntelligenceKind; label: string }[] = [
  { value: "credential", label: "凭据" },
  { value: "lead", label: "重要线索" },
  { value: "sensitive_data", label: "敏感数据" },
];
const STATUS: Record<IntelligenceKind, Record<string, string>> = {
  credential: {
    unverified: "未验证",
    verified: "验证成功",
    invalid: "无效",
  },
  lead: {
    pending: "待跟进",
    in_progress: "进行中",
    dismissed: "已放弃",
    converted: "已转化",
  },
  sensitive_data: {
    suspected: "疑似",
    confirmed: "已确认",
    dismissed: "已放弃",
  },
};

function conversationHref(item: TaskIntelligence) {
  return `/function/tasks/detail?id=${item.task_id}&tab=sessions${item.source_session ? `&session=${encodeURIComponent(item.source_session)}` : ""}`;
}

function AssetLinks({ ids, onNavigate }: { ids: number[]; onNavigate?: () => void }) {
  return ids.length ? (
    <span className="inline-flex flex-wrap gap-x-2 gap-y-1">
      {ids.map((id) => (
        <Link
          key={id}
          href={`/function/assets?asset=${id}`}
          onClick={onNavigate}
          className="underline underline-offset-2"
          aria-label={`查看资产 #${id}`}
        >
          #{id}
        </Link>
      ))}
    </span>
  ) : (
    <>无</>
  );
}

export function IntelligencePanel({
  scope,
  scopeId,
  onNavigate,
}: {
  scope: "tasks" | "assets";
  scopeId: string;
  onNavigate?: () => void;
}) {
  const [kind, setKind] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const [search, setSearch] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [data, setData] = React.useState<IntelligencePage | null>(null);
  const [error, setError] = React.useState<Error | null>(null);
  const [refresh, setRefresh] = React.useState(0);
  const [selected, setSelected] = React.useState<TaskIntelligence | null>(null);
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => {
    if (data)
      setSelected((current) => (current ? (data.items.find((item) => item.id === current.id) ?? current) : null));
  }, [data]);
  React.useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim());
      setPage(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: refresh explicitly reloads this resource after a user action.
  React.useEffect(() => {
    let alive = true;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
        if (kind !== "all") params.set("kind", kind);
        if (status !== "all") params.set("status", status);
        if (query) params.set("q", query);
        const result = await api.intelligence(scope, scopeId, params);
        if (alive) {
          setData(result);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e as Error);
      } finally {
        busy = false;
      }
    };
    void load();
    const timer = setInterval(() => {
      if (!document.hidden) void load();
    }, 8000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [scope, scopeId, kind, status, query, page, refresh]);
  const open = (item: TaskIntelligence) => setSelected(item);
  const close = () => setSelected(null);
  const navigate = () => {
    close();
    onNavigate?.();
  };
  const update = async (value: string) => {
    if (!selected) return;
    setSaving(true);
    try {
      await api.updateIntelligence(selected.task_id, selected.id, value);
      setSelected((item) => (item ? { ...item, status: value } : null));
      setRefresh((n) => n + 1);
      toast.success("状态已更新");
    } catch (e) {
      toast.error(`更新失败：${String((e as Error)?.message ?? e)}`);
    } finally {
      setSaving(false);
    }
  };
  const statusOptions = kind === "all" ? {} : STATUS[kind as IntelligenceKind];
  return (
    <div className="flex min-w-0 flex-col gap-4">
      {data && !data.enabled && scope === "tasks" ? (
        <Alert>
          <AlertTitle>任务情报采集未开启</AlertTitle>
          <AlertDescription>
            已保存的情报仍可查看；开启后 Agent 才会记录新的凭据、线索与敏感数据。前往{" "}
            <Link href="/system/settings" className="underline">
              系统设置
            </Link>{" "}
            打开「任务情报采集」。
          </AlertDescription>
        </Alert>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>{scope === "tasks" ? "任务情报" : "资产关联情报"}</CardTitle>
          <CardDescription>
            Agent 执行过程中实际获取的凭据、重要线索与敏感数据。人工定级后不会被 Agent
            的重复上报覆盖，重复记录自动去重。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex min-w-0 flex-col gap-4">
          <Tabs
            value={kind}
            onValueChange={(value) => {
              setKind(value);
              setStatus("all");
              setPage(0);
            }}
          >
            <TabsList className="max-w-full overflow-x-auto">
              <TabsTrigger value="all">
                全部
                {data ? Object.values(data.counts).reduce((a, b) => a + b, 0) : ""}
              </TabsTrigger>
              {KINDS.map((item) => (
                <TabsTrigger key={item.value} value={item.value}>
                  <ToneDot tone={statusMeta("intelligence", item.value).tone} />
                  {item.label} {data?.counts[item.value] ?? 0}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              aria-label="搜索情报"
              placeholder="搜索标题、内容、证据或记录者"
              value={search}
              maxLength={200}
              onChange={(e) => setSearch(e.target.value)}
              className="min-w-40 flex-1"
            />
            {kind !== "all" ? (
              <Select
                value={status}
                onValueChange={(value) => {
                  setStatus(value);
                  setPage(0);
                }}
              >
                <SelectTrigger aria-label="按状态筛选" className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="all">全部状态</SelectItem>
                    {Object.entries(statusOptions).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            ) : null}
            <Button variant="outline" onClick={() => setRefresh((n) => n + 1)}>
              <RefreshCwIcon data-icon="inline-start" />
              刷新
            </Button>
          </div>
          {error ? (
            <Alert variant="destructive">
              <AlertTitle>加载失败</AlertTitle>
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          ) : null}
          {!data && !error ? (
            <Skeleton className="h-40 w-full" />
          ) : data?.items.length ? (
            <Table className="min-w-[68rem] table-fixed">
              <colgroup>
                <col className="w-[20%]" />
                <col className="w-[35%]" />
                <col className="w-[8%]" />
                <col className="w-[12%]" />
                <col className="w-[6%]" />
                <col className="w-[12%]" />
                <col className="w-[7%]" />
              </colgroup>
              <TableHeader>
                <TableRow>
                  <TableHead>情报</TableHead>
                  <TableHead>内容与证据</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>资产</TableHead>
                  <TableHead>记录时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="align-top whitespace-normal">
                      <div className="flex min-w-0 flex-col items-start gap-1">
                        <StatusBadge domain="intelligence" value={item.kind} />
                        <span className="max-w-full [overflow-wrap:anywhere]">{item.title}</span>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <div className="flex min-w-0 flex-col gap-2">
                        <p className="max-h-24 overflow-hidden whitespace-pre-wrap break-all text-sm">
                          {item.content}
                        </p>
                        <div className="flex flex-col gap-1 text-muted-foreground text-xs">
                          <span>证据</span>
                          <p className="whitespace-pre-wrap break-all">{item.evidence.length > 220 ? `${item.evidence.slice(0, 220)}…` : item.evidence}</p>
                          {item.evidence.length > 220 ? (
                            <button type="button" className="text-left underline" onClick={() => open(item)}>
                              查看全部
                            </button>
                          ) : null}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <div className="flex flex-col items-start gap-1">
                        <Badge variant="outline">{STATUS[item.kind]?.[item.status] ?? item.status}</Badge>
                        <span className="text-muted-foreground text-xs">
                          {item.confidence === "observed" ? "直接观察" : "推断"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <div className="flex flex-col gap-1">
                        <Link href={conversationHref(item)} onClick={navigate} className="underline">
                          {item.source_session ? "定位会话" : "所属任务"}
                        </Link>
                        <span className="text-muted-foreground text-xs">
                          任务 {item.task_id} · {item.worker || "Agent"}
                        </span>
                        {item.inherited ? <Badge variant="outline">继承</Badge> : null}
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <AssetLinks ids={item.asset_ids} onNavigate={navigate} />
                    </TableCell>
                    <TableCell className="align-top whitespace-normal text-xs">
                      {new Date(item.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <Button size="sm" variant="outline" onClick={() => open(item)}>
                        详情
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : data ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>暂无情报</EmptyTitle>
                <EmptyDescription>
                  {query || kind !== "all" || status !== "all"
                    ? "没有匹配当前筛选条件的情报，试试调整关键词或类别。"
                    : data.enabled
                      ? "Agent 发现凭据、线索或敏感数据后会自动记录在这里。"
                      : "任务情报采集未开启；已保存的情报仍可查看，开启后 Agent 才会记录新情报。"}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : null}
        </CardContent>
        <CardFooter className="flex items-center justify-between gap-2">
          <span className="text-muted-foreground text-sm">
            共 {data?.total ?? 0} 条情报
          </span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((n) => n - 1)}>
              上一页
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!data || (page + 1) * 25 >= data.total}
              onClick={() => setPage((n) => n + 1)}
            >
              下一页
            </Button>
          </div>
        </CardFooter>
      </Card>
      <Dialog
        open={!!selected}
        onOpenChange={(value) => {
          if (!value) close();
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{selected?.title ?? "情报详情"}</DialogTitle>
            <DialogDescription>凭据发现不等于验证成功；人工定级后不会被 Agent 覆盖。</DialogDescription>
          </DialogHeader>
          {selected ? (
            <div className="flex min-w-0 flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge domain="intelligence" value={selected.kind} />
                <Badge variant="outline">
                  {selected.confidence === "observed" ? "直接观察" : "推断"}
                </Badge>
                <span className="text-muted-foreground text-xs">
                  任务 {selected.task_id} · {selected.worker || "Agent"}
                </span>
              </div>
              {scope === "tasks" && !selected.inherited ? (
                <Select value={selected.status} disabled={saving} onValueChange={(value) => void update(value)}>
                  <SelectTrigger aria-label="更新状态" className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {Object.entries(STATUS[selected.kind] ?? {}).map(([value, label]) => (
                        <SelectItem key={value} value={value}>
                          {label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-muted-foreground text-sm">
                  {STATUS[selected.kind]?.[selected.status] ?? selected.status}（继承情报或资产视图下只读）
                </p>
              )}
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm">内容</span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={async () => {
                    if (await copyText(selected.content)) toast.success("已复制");
                    else toast.error("复制失败");
                  }}
                >
                  <CopyIcon data-icon="inline-start" />
                  复制
                </Button>
              </div>
              <pre className="max-h-48 overflow-auto rounded-lg bg-muted p-3 whitespace-pre-wrap break-all text-xs">
                {selected.content}
              </pre>
              <p className="text-sm">证据</p>
              <pre className="max-h-48 overflow-auto rounded-lg bg-muted p-3 whitespace-pre-wrap break-all text-xs">
                {selected.evidence}
              </pre>
              <div className="flex flex-wrap gap-2 text-muted-foreground text-xs">
                <span>
                  关联资产
                  <AssetLinks ids={selected.asset_ids} onNavigate={navigate} />
                </span>
                <span>
                  记录于 {new Date(selected.created_at).toLocaleString()}
                </span>
              </div>
              <Link href={conversationHref(selected)} onClick={navigate} className="text-sm underline">
                {selected.source_session ? "跳转到来源会话" : "查看所属任务"}
              </Link>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
