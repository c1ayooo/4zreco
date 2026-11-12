"use client";
import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { toast } from "sonner";

import { FindingCaseMembers, FindingCaseReviewPanel, FindingSeverityCounts } from "@/components/finding-case-list";
import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingCase, FindingCaseEvent } from "@/lib/types";

// C1 归并文件夹详情（移植自 ARTEX 0.3.29 findings/case/page.tsx，i18n 剥离；
// 统一报告用本地版本号校验编辑保存，未移植 ARTEX 的 reporter 重生成端点）。

type FindingCaseDetail = { case: FindingCase; events: FindingCaseEvent[] };

const CASE_ACTIONS: Record<string, string> = {
  merge: "归并",
  detach: "移出",
  member_deleted: "成员删除",
  report_updated: "统一报告更新",
};
const CASE_ACTORS: Record<string, string> = {
  reporter: "报告 Agent",
  human: "人工",
  system: "系统",
};

function CaseDetail() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";
  const contextTask = params.get("context_task") ?? undefined;
  const [data, setData] = React.useState<FindingCaseDetail | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [selected, setSelected] = React.useState<Set<string>>(() => new Set());
  const [refresh, setRefresh] = React.useState(0);
  // 编辑态：title/severity/severity_reason/report 一次保存；version 取装载时的
  // case.version，提交后服务端校验（不符 409 → 提示重读）。
  const [editing, setEditing] = React.useState(false);
  const [draft, setDraft] = React.useState({ title: "", report: "", severity: "", severity_reason: "" });
  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function load() {
      try {
        const v = await api.findingCase(id, contextTask);
        if (active) {
          setData(v);
          setError("");
        }
      } catch (e) {
        if (active) setError((e as Error).message);
      } finally {
        if (active) timer = setTimeout(load, 5000);
      }
    }
    if (id) void load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [id, contextTask, refresh]);
  const readOnly = !!contextTask && contextTask !== data?.case.task_id;
  const select = (fid: string, on: boolean) =>
    setSelected((v) => {
      const n = new Set(v);
      if (on) n.add(fid);
      else n.delete(fid);
      return n;
    });
  function startEdit(c: FindingCase) {
    setDraft({ title: c.title, report: c.report ?? "", severity: c.severity, severity_reason: c.severity_reason });
    setEditing(true);
  }
  async function saveReport() {
    if (!data) return;
    setBusy(true);
    try {
      await api.updateFindingCaseReport(id, data.case.version, {
        title: draft.title.trim(),
        report: draft.report,
        severity: draft.severity,
        severity_reason: draft.severity_reason.trim(),
      });
      toast.success("统一报告已保存");
      setEditing(false);
      setRefresh((v) => v + 1);
    } catch (e) {
      // 409 = 版本冲突（证据已变更），必须重读材料再生成，不能仅换 version 重试。
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function detach() {
    setBusy(true);
    try {
      for (const fid of selected) await api.removeFindingCaseMember(id, fid, "人工撤销归并");
      setSelected(new Set());
      setRefresh((v) => v + 1);
      toast.success("已移出所选记录");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!id)
    return (
      <Alert>
        <AlertDescription>缺少文件夹 id。</AlertDescription>
      </Alert>
    );
  if (!data)
    return error ? (
      <Alert>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    ) : (
      <div className="flex justify-center p-10">
        <Spinner />
      </div>
    );
  const c = data.case;
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button asChild variant="outline">
          <Link href="/function/findings">返回发现</Link>
        </Button>
        <h1 className="font-semibold text-xl">{c.title}</h1>
        <FindingSeverityCounts counts={c} />
      </div>
      {error ? (
        <Alert>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {!c.active ? (
        <Alert>
          <AlertDescription>该文件夹已解散（成员少于两条），仅保留历史记录。</AlertDescription>
        </Alert>
      ) : null}
      {readOnly ? (
        <Alert>
          <AlertDescription>继承文件夹只读：请到来源任务操作。</AlertDescription>
        </Alert>
      ) : (
        <FindingCaseReviewPanel taskId={c.task_id ?? undefined} />
      )}
      <Tabs defaultValue="report">
        <TabsList>
          <TabsTrigger value="report">统一报告</TabsTrigger>
          <TabsTrigger value="members">成员上报（{c.count}）</TabsTrigger>
          <TabsTrigger value="history">归并历史</TabsTrigger>
        </TabsList>
        <TabsContent value="report">
          <Card>
            <CardHeader>
              <CardTitle>统一报告</CardTitle>
              <CardDescription>
                汇总全部成员证据的完整报告；各成员仍有独立报告、评级和证据。
                {c.report_version !== c.version ? "统一报告待更新：成员或证据已有变更。" : ""}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex min-w-0 flex-col gap-4">
              {!readOnly && c.active ? (
                <div className="flex flex-wrap items-center gap-2">
                  {editing ? (
                    <>
                      <Button variant="outline" onClick={saveReport} disabled={busy}>
                        {busy ? <Spinner /> : null}
                        保存
                      </Button>
                      <Button variant="ghost" onClick={() => setEditing(false)} disabled={busy}>
                        取消
                      </Button>
                    </>
                  ) : (
                    <Button variant="outline" onClick={() => startEdit(c)}>
                      编辑统一报告
                    </Button>
                  )}
                </div>
              ) : null}
              {c.report_version !== c.version && !editing ? (
                <Alert>
                  <AlertDescription>
                    统一报告尚未生成或已过期，下列内容不能视为完整复现；请读取全部成员证据后补齐。
                  </AlertDescription>
                </Alert>
              ) : null}
              {editing ? (
                <div className="flex min-w-0 flex-col gap-3">
                  <input
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    value={draft.title}
                    onChange={(e) => setDraft((d) => ({ ...d, title: e.target.value }))}
                    aria-label="漏洞名称"
                    placeholder="同一实际缺陷的名称"
                  />
                  <div className="flex flex-wrap gap-3 text-sm">
                    <label className="flex items-center gap-2">
                      统一评级
                      <select
                        className="rounded-md border bg-background px-2 py-1"
                        value={draft.severity}
                        onChange={(e) => setDraft((d) => ({ ...d, severity: e.target.value }))}
                        aria-label="统一评级"
                      >
                        <option value="">未评定</option>
                        <option value="critical">严重</option>
                        <option value="high">高危</option>
                        <option value="medium">中危</option>
                        <option value="low">低危</option>
                      </select>
                    </label>
                  </div>
                  <Textarea
                    className="min-h-96 font-mono text-sm"
                    value={draft.report}
                    onChange={(e) => setDraft((d) => ({ ...d, report: e.target.value }))}
                    aria-label="统一报告 Markdown"
                    placeholder={"# 标题\n## 概述\n## 影响\n## 前置条件\n## 复现步骤\n## 证据\n## PoC\n## 根因分析\n## 修复建议"}
                  />
                  <input
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                    value={draft.severity_reason}
                    onChange={(e) => setDraft((d) => ({ ...d, severity_reason: e.target.value }))}
                    aria-label="评级依据"
                    placeholder="基于已验证影响的评级依据（不直接取成员最高等级）"
                  />
                </div>
              ) : c.report ? (
                <Markdown text={c.report} />
              ) : (
                <p className="text-muted-foreground text-sm">统一报告待更新。</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="members">
          <Card>
            <CardHeader>
              <CardTitle>成员上报</CardTitle>
              <CardDescription>勾选成员可将其移出文件夹（会写入人工否决对，阻止再次自动归并）。</CardDescription>
            </CardHeader>
            <CardContent>
              {!readOnly && selected.size > 0 ? (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="outline" disabled={busy}>
                      移出所选（{selected.size}）
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>移出归并组</AlertDialogTitle>
                      <AlertDialogDescription>
                        移出后这些记录与文件夹内其余成员将被永久禁止再次归并（人工否决）。确定继续？
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>取消</AlertDialogCancel>
                      <AlertDialogAction onClick={detach}>确认移出</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              ) : null}
              <FindingCaseMembers
                caseId={id}
                version={c.version}
                selectedIds={selected}
                onSelect={readOnly ? undefined : select}
                contextTask={contextTask}
              />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>归并历史</CardTitle>
              <CardDescription>{c.reason}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {data.events.map((e) => (
                <div key={e.id} className="border-b pb-3 text-sm">
                  <p>
                    {CASE_ACTORS[e.actor] ?? e.actor} · {CASE_ACTIONS[e.action] ?? e.action} ·{" "}
                    {new Date(e.created_at).toLocaleString("zh-CN")}
                  </p>
                  <p className="text-muted-foreground">
                    {e.reason}
                    {e.finding_ids.length > 0 ? ` · #${e.finding_ids.join(" / #")}` : ""}
                  </p>
                </div>
              ))}
              {data.events.length === 0 ? <p className="text-muted-foreground text-sm">暂无事件。</p> : null}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingCasePage() {
  return (
    <React.Suspense fallback={null}>
      <CaseDetail />
    </React.Suspense>
  );
}
