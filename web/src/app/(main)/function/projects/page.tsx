"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import {
  ArchiveIcon,
  CalendarIcon,
  FolderKanbanIcon,
  ListTodoIcon,
  MessageSquareIcon,
  PencilIcon,
  PlusIcon,
  TargetIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { ScopeTextEditor } from "@/components/scope-text-editor";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { parseCompanyScopeText } from "@/lib/company-scope";
import type { Project, ProjectScope } from "@/lib/types";
import { useProjectStore } from "@/stores/project/project-provider";

// 项目管理：项目 = 任务/对话的归属主轴。范围仅作组织定义（本项目无资产围栏）。
export default function ProjectsPage() {
  const setProject = useProjectStore((s) => s.setProject);
  const reloadProjects = useProjectStore((s) => s.reloadProjects);
  const currentProjectId = useProjectStore((s) => s.projectId);
  const router = useRouter();
  // 点卡片 = 切到该项目并去任务页（与侧栏切换器同一条路：写全局 store + 深链对齐）。
  const switchTo = React.useCallback(
    (id: number) => {
      setProject(id);
      void router.push(`/function/tasks?project_id=${id}`);
    },
    [setProject, router],
  );
  // 新建任务 = 切到该项目并直接拉起任务页的创建面板（?create=1 打开面板，
  // &project_id= 预选归属项目——深链语义见 tasks/page.tsx 的两个 effect）。
  const newTaskIn = React.useCallback(
    (id: number) => {
      setProject(id);
      void router.push(`/function/tasks?create=1&project_id=${id}`);
    },
    [setProject, router],
  );

  const [list, setList] = React.useState<Project[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  // create/edit 弹窗：target=null 新建，否则编辑
  const [editTarget, setEditTarget] = React.useState<Project | null | undefined>(undefined);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [archived, setArchived] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  // 范围弹窗
  const [scopeTarget, setScopeTarget] = React.useState<Project | null>(null);
  const [scopeText, setScopeText] = React.useState("");
  const [scopeReason, setScopeReason] = React.useState("");
  const [scopeBusy, setScopeBusy] = React.useState(false);
  // 删除确认
  const [deleteTarget, setDeleteTarget] = React.useState<Project | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const [projects] = await Promise.all([api.projects(), reloadProjects()]);
      setList(projects);
    } catch (e) {
      toast.error(`加载项目失败：${(e as Error).message}`);
    } finally {
      setLoaded(true);
    }
  }, [reloadProjects]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // ?create=1 深链（侧栏切换器/对话页入口）直接打开新建弹窗。
  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("create") === "1") setEditTarget(null);
  }, []);

  function openCreate() {
    setName("");
    setDescription("");
    setArchived(false);
    setEditTarget(null);
  }

  function openEdit(p: Project) {
    setName(p.name);
    setDescription(p.description ?? "");
    setArchived(p.status === "archived");
    setEditTarget(p);
  }

  async function save() {
    if (!name.trim() || saving) return;
    setSaving(true);
    try {
      if (editTarget == null) {
        const created = await api.createProject(name.trim(), description.trim());
        toast.success(`项目「${created.name}」已创建`);
        setProject(created.id);
      } else {
        await api.updateProject(editTarget.id, {
          name: name.trim(),
          description: description.trim(),
          status: archived ? "archived" : "active",
        });
        toast.success("项目已保存");
      }
      setEditTarget(undefined);
      await load();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function addScope() {
    if (!scopeTarget || !scopeText.trim() || scopeBusy) return;
    setScopeBusy(true);
    try {
      const r = await api.addProjectScope(scopeTarget.id, scopeText, scopeReason.trim());
      const problems = [...r.errors];
      if (r.added === 0 && problems.length === 0) problems.push("没有新增规则（可能全部与已有规则重复）");
      if (problems.length > 0) {
        toast.warning(`新增 ${r.added} 条` + (r.skipped ? `，跳过重复 ${r.skipped} 条` : ""), {
          description: problems.slice(0, 4).join("\n"),
        });
      } else {
        toast.success(`新增 ${r.added} 条范围规则` + (r.skipped ? `，跳过重复 ${r.skipped} 条` : ""));
      }
      setScopeText("");
      setScopeReason("");
      await load();
      // 弹窗内的项目行同步刷新
      const fresh = (await api.projects()).find((p) => p.id === scopeTarget.id) ?? null;
      setScopeTarget(fresh);
    } catch (e) {
      toast.error(`保存范围失败：${(e as Error).message}`);
    } finally {
      setScopeBusy(false);
    }
  }

  async function removeScope(p: Project, rule: ProjectScope) {
    try {
      await api.deleteProjectScope(p.id, rule.id);
      const fresh = (await api.projects()).find((x) => x.id === p.id) ?? null;
      setScopeTarget(fresh);
      await load();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  async function remove() {
    if (!deleteTarget || deleting) return;
    setDeleting(true);
    try {
      await api.deleteProject(deleteTarget.id);
      toast.success(`项目「${deleteTarget.name}」已删除，关联任务/对话已解除挂载`);
      setDeleteTarget(null);
      await load();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-semibold text-2xl tracking-tight">项目</h1>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => void router.push("/function/tasks?create=1")}
              title="跳转到任务页并打开创建面板（默认挂当前项目）"
            >
              <ListTodoIcon className="size-4" /> 新建任务
            </Button>
            <Button onClick={openCreate}>
              <PlusIcon className="size-4" /> 新建项目
            </Button>
          </div>
        </div>

      {!loaded ? (
        <div className="text-muted-foreground py-16 text-center text-sm">加载中…</div>
      ) : list.length === 0 ? (
        <div className="text-muted-foreground flex flex-col items-center gap-2 py-16 text-center text-sm">
          <FolderKanbanIcon className="text-muted-foreground/50 size-10" />
          还没有项目。新建一个，建任务和对话时就能挂载归属。
        </div>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((p) => (
            <div
              key={p.id}
              onClick={() => switchTo(p.id)}
              title="切换到此项目"
              className={
                "flex cursor-pointer flex-col gap-2 rounded-xl border p-4 transition-shadow hover:shadow-sm" +
                (p.id === currentProjectId ? " ring-primary/40 ring-2" : "")
              }
            >
              <div className="flex min-w-0 items-center gap-2">
                <span className="min-w-0 flex-1 truncate font-medium">{p.name}</span>
                {p.id === currentProjectId && <Badge className="shrink-0 px-1.5 py-0 text-[10px]">使用中</Badge>}
                {p.status === "archived" && (
                  <Badge variant="outline" className="shrink-0 px-1.5 py-0 text-[10px]">
                    已归档
                  </Badge>
                )}
              </div>
              {p.description && <p className="text-muted-foreground line-clamp-2 text-xs">{p.description}</p>}
              <div className="text-muted-foreground flex items-center gap-3 text-xs tabular-nums">
                <span className="inline-flex items-center gap-1">
                  <ListTodoIcon className="size-3" /> {p.task_count} 任务
                </span>
                <span className="inline-flex items-center gap-1">
                  <MessageSquareIcon className="size-3" /> {p.conversation_count} 对话
                </span>
                <span className="inline-flex items-center gap-1">
                  <TargetIcon className="size-3" /> 范围 {p.scope.length} 条
                </span>
              </div>
              {p.scope.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {p.scope.slice(0, 3).map((r) => (
                    <Badge key={r.id} variant="secondary" className="px-1.5 py-0 font-mono text-[10px]">
                      {r.raw}
                    </Badge>
                  ))}
                  {p.scope.length > 3 && (
                    <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                      +{p.scope.length - 3}
                    </Badge>
                  )}
                </div>
              )}
              <div className="text-muted-foreground mt-auto flex items-center gap-2 pt-1 text-[11px]">
                <CalendarIcon className="size-3" />
                {new Date(p.created_at).toLocaleDateString()}
                <span className="ml-auto flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    title={`在「${p.name}」下新建任务（切换到此项目并打开创建面板）`}
                    onClick={(e) => {
                      e.stopPropagation();
                      newTaskIn(p.id);
                    }}
                  >
                    <PlusIcon className="size-3.5" /> 新建任务
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={(e) => {
                      e.stopPropagation();
                      openEdit(p);
                    }}
                  >
                    <PencilIcon className="size-3.5" /> 编辑
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={(e) => {
                      e.stopPropagation();
                      setScopeTarget(p);
                      setScopeText("");
                      setScopeReason("");
                    }}
                  >
                    <TargetIcon className="size-3.5" /> 范围
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:text-destructive h-7 px-2 text-xs"
                    onClick={(e) => {
                      e.stopPropagation();
                      setDeleteTarget(p);
                    }}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 新建 / 编辑 */}
      <Dialog open={editTarget !== undefined} onOpenChange={(o) => !o && setEditTarget(undefined)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editTarget == null ? "新建项目" : "编辑项目"}</DialogTitle>
            <DialogDescription>项目是任务与对话的归属主轴；删除项目不会删除任务或对话。</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="flex flex-col gap-1.5">
              <span className="text-sm">名称</span>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如：某大学校内网" />
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="text-sm">描述</span>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                placeholder="委托背景、目标说明（可选）"
              />
            </label>
            {editTarget != null && (
              <label className="flex items-center justify-between gap-2">
                <span className="text-sm">归档</span>
                <Switch checked={archived} onCheckedChange={setArchived} />
              </label>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(undefined)}>
              取消
            </Button>
            <Button onClick={save} disabled={!name.trim() || saving}>
              {saving ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 范围编辑 */}
      <Dialog open={scopeTarget != null} onOpenChange={(o) => !o && setScopeTarget(null)}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>项目范围 — {scopeTarget?.name}</DialogTitle>
            <DialogDescription>范围是项目的组织定义；建任务挂本项目时种子进任务范围。</DialogDescription>
          </DialogHeader>
          <ScopeTextEditor
            id="project-scope-input"
            value={scopeText}
            onValueChange={setScopeText}
            parsed={parseCompanyScopeText(scopeText)}
            label="追加范围"
            description="每行一条，自动识别域名、IP、CIDR、ICP 备案和关键词。"
          />
          <label className="flex flex-col gap-1.5">
            <span className="text-muted-foreground text-xs">归属依据（可选，记录为什么这条范围属于本项目）</span>
            <Input
              value={scopeReason}
              onChange={(e) => setScopeReason(e.target.value)}
              placeholder="例如：委托书第 2 条"
            />
          </label>
          <div className="flex justify-end">
            <Button onClick={addScope} disabled={!scopeText.trim() || scopeBusy}>
              {scopeBusy ? "保存中…" : "追加范围"}
            </Button>
          </div>
          {scopeTarget && scopeTarget.scope.length > 0 && (
            <ScrollArea className="max-h-56 rounded-lg border">
              <div className="flex flex-col divide-y">
                {scopeTarget.scope.map((rule) => (
                  <div key={rule.id} className="flex items-center gap-2 px-3 py-2 text-sm">
                    <Badge variant="secondary" className="shrink-0 px-1.5 py-0 text-[10px]">
                      {scopeKindLabel(rule.kind)}
                    </Badge>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs">{rule.raw}</span>
                    {rule.reason && (
                      <span className="text-muted-foreground hidden truncate text-[11px] sm:inline">{rule.reason}</span>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:text-destructive h-6 shrink-0 px-1.5"
                      onClick={() => removeScope(scopeTarget, rule)}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <Dialog open={deleteTarget != null} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>删除项目「{deleteTarget?.name}」？</DialogTitle>
            <DialogDescription>
              项目范围随之删除；挂在本项目下的 {deleteTarget?.task_count ?? 0} 个任务与{" "}
              {deleteTarget?.conversation_count ?? 0} 个对话会解除挂载（本身不被删除）。此操作不可撤销。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button variant="destructive" onClick={remove} disabled={deleting}>
              <ArchiveIcon className="size-4" /> {deleting ? "删除中…" : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function scopeKindLabel(kind: ProjectScope["kind"]): string {
  switch (kind) {
    case "domain":
      return "域名";
    case "ip":
      return "IP";
    case "cidr":
      return "CIDR";
    case "icp":
      return "ICP";
    case "keyword":
      return "关键词";
  }
}
