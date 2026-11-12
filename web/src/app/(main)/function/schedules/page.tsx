"use client";

// 日历式计划任务（移植自 ARTEX 0.3.29 A7 的 schedules/page.tsx，877 行）。
// 本仓库无 i18n 体系：全部文案中文硬编码（剥离 useLiveTranslation/localizedError）。
// 布局/令牌/组件遵循本仓库 UI 规范（~/.zcode/UI_DESIGN.md）：语义状态令牌、
// table-fixed + 响应式列存活 + matchMedia 同步展开行 colSpan、TablePagination、
// AlertDialog 确认、Empty 空态、Skeleton 加载；ARTEX 的 DateSelect/TimeSelect/
// ScheduleNameEditor 组件本地不存在，分别以原生 <input type="date|time"> 与
// 本文件内的行内名称编辑器等价替代。

import * as React from "react";

import {
  CalendarClock,
  ChevronDown,
  ChevronRight,
  Plus,
  Search,
  Trash2,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

import { RemarkEditor } from "@/components/remark-editor";
import { TablePagination } from "@/components/table-pagination";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, type ScheduleInput } from "@/lib/api";
import { scheduleDisplay } from "@/lib/schedule-display";
import type { Task, TaskSchedule } from "@/lib/types";

const blank: ScheduleInput = {
  name: "",
  schedule_type: "weekly",
  weekdays: [6, 7],
  start_time: "18:00",
  end_time: "",
  task_ids: [],
  timezone_mode: "beijing",
  start_immediately: false,
};

type ScheduleHistoryEntry = NonNullable<TaskSchedule["history"]>[number];

// 状态一律语义令牌（success/warning/info/destructive/muted），禁止手写调色板类。
function historyEventClass(event: ScheduleHistoryEntry) {
  if (!event.success) return "border-destructive/30 bg-destructive/10 text-destructive";
  if (event.action === "running" || event.action === "resume") {
    return "border-success/30 bg-success/10 text-success";
  }
  if (event.action === "outside" || event.action === "pause" || event.action === "paused") {
    return "border-warning/30 bg-warning/10 text-warning";
  }
  return "border-border bg-muted text-muted-foreground";
}

function historyDotClass(event: ScheduleHistoryEntry) {
  if (!event.success) return "bg-destructive";
  if (event.action === "running" || event.action === "resume") return "bg-success";
  if (event.action === "outside" || event.action === "pause" || event.action === "paused") return "bg-warning";
  return "bg-muted-foreground/40";
}

function statusClass(status: TaskSchedule["status"]) {
  return (
    {
      waiting: "border-info/30 bg-info/10 text-info",
      running: "border-success/30 bg-success/10 text-success",
      outside: "border-warning/30 bg-warning/10 text-warning",
      completed: "border-border bg-muted text-muted-foreground",
      error: "border-destructive/30 bg-destructive/10 text-destructive",
      paused: "border-border bg-muted text-muted-foreground",
    } as Record<TaskSchedule["status"], string>
  )[status];
}

// ScheduleNameEditor 的本地等价物：点击文本进入行内编辑，Enter 或失焦保存、
// Esc 取消。中文文案硬编码（ARTEX 版走 inlineEditor.* 翻译键）。
function ScheduleNameEditor({ value, label, onSave }: { value: string; label: string; onSave: (name: string) => Promise<void> }) {
  const [editing, setEditing] = React.useState(false);
  const [draft, setDraft] = React.useState(value);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!editing) setDraft(value);
  }, [editing, value]);

  async function commit() {
    const next = draft.trim();
    if (!next || next === value) {
      setDraft(value);
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      await onSave(next);
      setEditing(false);
    } catch (e) {
      toast.error(`重命名失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  if (!editing) {
    return (
      <button
        type="button"
        aria-label={label}
        className="flex w-full min-w-0 items-center gap-1 truncate rounded text-left hover:bg-muted/60"
        title={value}
        onClick={() => setEditing(true)}
      >
        <span className="truncate">{value}</span>
      </button>
    );
  }
  return (
    <Input
      autoFocus
      value={draft}
      disabled={saving}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => void commit()}
      onKeyDown={(e) => {
        if (e.key === "Enter") void commit();
        if (e.key === "Escape") {
          setDraft(value);
          setEditing(false);
        }
      }}
      className="h-8"
    />
  );
}

// 不可逆操作确认（删除/批量删除）统一 AlertDialog。
function ConfirmDialog({
  title,
  description,
  confirmText,
  trigger,
  onConfirm,
}: {
  title: string;
  description: string;
  confirmText: string;
  trigger: React.ReactNode;
  onConfirm: () => Promise<void>;
}) {
  const [open, setOpen] = React.useState(false);
  const [pending, setPending] = React.useState(false);
  return (
    <AlertDialog open={open} onOpenChange={(next) => !pending && setOpen(next)}>
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>取消</AlertDialogCancel>
          <AlertDialogAction
            disabled={pending}
            onClick={async (event) => {
              event.preventDefault();
              setPending(true);
              try {
                await onConfirm();
                setOpen(false);
              } finally {
                setPending(false);
              }
            }}
          >
            {pending && <Spinner data-icon="inline-start" />}
            {confirmText}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function ScheduleTimeline({ schedule, loading }: { schedule?: TaskSchedule; loading: boolean }) {
  const { formatTime, historyActionText } = scheduleDisplay();
  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 text-muted-foreground text-sm">
        <Spinner className="size-4" />
        加载运行时间线…
      </div>
    );
  }
  // The API returns newest first. Keep that order so the latest transition is
  // visible immediately when a row is expanded.
  const events = schedule?.history ?? [];
  if (!events.length) {
    return <div className="py-4 text-muted-foreground text-sm">暂无运行记录，计划进入第一个窗口后会显示时间线。</div>;
  }
  return (
    <div className="grid gap-3 rounded-lg bg-muted/20 p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="font-medium text-sm">运行时间线</div>
        <span className="text-muted-foreground text-xs">最近 {Math.min(events.length, 20)} 条记录</span>
      </div>
      <div className="grid gap-0">
        {events.slice(0, 20).map((event, index) => (
          <div key={event.id} className="relative flex gap-3 pb-3 last:pb-0">
            {index < Math.min(events.length, 20) - 1 ? (
              <span className="absolute top-4 bottom-0 left-[5px] w-px bg-border" aria-hidden="true" />
            ) : null}
            <span
              className={`relative mt-1.5 size-3 shrink-0 rounded-full border-2 border-background shadow-sm ${historyDotClass(event)}`}
              title={historyActionText(event.action)}
            />
            <div className="min-w-0 flex-1 rounded-md border bg-background px-3 py-2">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant="outline" className={historyEventClass(event)}>
                  {historyActionText(event.action)}
                </Badge>
                <span className="text-muted-foreground">{formatTime(event.created_at)}</span>
                <span className="text-muted-foreground">{event.task_id ? `任务 #${event.task_id}` : "计划"}</span>
              </div>
              {event.message ? (
                <div className={`mt-1 text-xs ${event.success ? "text-muted-foreground" : "text-destructive"}`}>
                  {event.message}
                </div>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScheduleForm({
  value,
  tasks,
  onSave,
  onCancel,
  saving,
}: {
  value: ScheduleInput;
  tasks: Task[];
  onSave: (v: ScheduleInput) => void;
  onCancel?: () => void;
  saving: boolean;
}) {
  const { weekdays } = scheduleDisplay();
  const [draft, setDraft] = React.useState(value);
  const [taskQuery, setTaskQuery] = React.useState("");
  const set = (patch: Partial<ScheduleInput>) => setDraft((v) => ({ ...v, ...patch }));
  const toggleTask = (id: number, checked: boolean) =>
    set({ task_ids: checked ? [...(draft.task_ids ?? []), id] : (draft.task_ids ?? []).filter((x) => x !== id) });
  const toggleDay = (day: number) =>
    set({
      weekdays: (draft.weekdays ?? []).includes(day)
        ? (draft.weekdays ?? []).filter((x) => x !== day)
        : [...(draft.weekdays ?? []), day].sort(),
    });
  const filteredTasks = React.useMemo(() => {
    const query = taskQuery.trim().toLowerCase();
    if (!query) return tasks;
    return tasks.filter((task) =>
      [String(task.id), task.name ?? "", task.description, task.goal].some((value) =>
        value.toLowerCase().includes(query),
      ),
    );
  }, [taskQuery, tasks]);
  let taskListContent: React.ReactNode;
  if (tasks.length === 0) {
    taskListContent = <span className="text-muted-foreground text-sm">暂无任务</span>;
  } else if (filteredTasks.length === 0) {
    taskListContent = <span className="text-muted-foreground text-sm">没有匹配的任务</span>;
  } else {
    taskListContent = filteredTasks.map((task) => (
      <div key={task.id} className="flex items-center gap-2 py-1 text-sm">
        <Checkbox
          id={`schedule-task-${task.id}`}
          checked={(draft.task_ids ?? []).includes(Number(task.id))}
          onCheckedChange={(v) => toggleTask(Number(task.id), !!v)}
        />
        <Label htmlFor={`schedule-task-${task.id}`} className="truncate">
          #{task.id} {task.name || task.description}
        </Label>
      </div>
    ));
  }
  return (
    <div className="grid gap-4">
      <div className="grid gap-2">
        <Label>计划名称</Label>
        <Input value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="例如：周末持续扫描" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-2">
          <Label>规则</Label>
          <Select
            value={draft.schedule_type}
            onValueChange={(value) => set({ schedule_type: value as ScheduleInput["schedule_type"] })}
          >
            <SelectTrigger className="h-10 w-full bg-background">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="weekly">按周</SelectItem>
              <SelectItem value="once">指定日期</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label>时区</Label>
          <Select
            value={draft.timezone_mode}
            onValueChange={(value) => set({ timezone_mode: value as ScheduleInput["timezone_mode"] })}
          >
            <SelectTrigger className="h-10 w-full bg-background">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="beijing">中国北京时间</SelectItem>
              <SelectItem value="system">系统当前时区</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      {draft.schedule_type === "once" ? (
        <div className="grid grid-cols-2 gap-3">
          <div className="grid gap-2">
            <Label>开始日期</Label>
            <Input
              type="date"
              value={draft.run_date ?? ""}
              onChange={(e) => set({ run_date: e.target.value })}
              aria-label="开始日期"
            />
          </div>
          <div className="grid gap-2">
            <Label>截止日期（可选）</Label>
            <Input
              type="date"
              value={draft.end_date ?? ""}
              onChange={(e) => set({ end_date: e.target.value })}
              aria-label="截止日期，可选"
            />
          </div>
        </div>
      ) : (
        <div className="grid gap-2">
          <Label>星期</Label>
          <div className="flex flex-wrap gap-3">
            {weekdays.map((label, index) => (
              <div key={label} className="flex items-center gap-2 text-sm">
                <Checkbox
                  id={`schedule-weekday-${index + 1}`}
                  checked={(draft.weekdays ?? []).includes(index + 1)}
                  onCheckedChange={() => toggleDay(index + 1)}
                />
                <Label htmlFor={`schedule-weekday-${index + 1}`}>{label}</Label>
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-2">
          <Label>开始时间</Label>
          <Input
            type="time"
            value={draft.start_time}
            onChange={(e) => set({ start_time: e.target.value })}
            aria-label="开始时间"
          />
        </div>
        <div className="grid gap-2">
          <Label>结束时间（可选）</Label>
          <Input
            type="time"
            value={draft.end_time ?? ""}
            onChange={(e) => set({ end_time: e.target.value })}
            aria-label="结束时间，可选"
          />
        </div>
      </div>
      <div className="flex items-center gap-2 text-sm">
        <Checkbox
          id="schedule-start-immediately"
          checked={draft.start_immediately}
          onCheckedChange={(v) => set({ start_immediately: !!v })}
        />
        <Label htmlFor="schedule-start-immediately">创建后立即启动，不等待第一个窗口</Label>
      </div>
      <div className="grid gap-2">
        <div className="flex items-center justify-between gap-3">
          <Label>绑定任务</Label>
          <span className="text-muted-foreground text-xs">已选 {(draft.task_ids ?? []).length} 个</span>
        </div>
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={taskQuery}
            onChange={(event) => setTaskQuery(event.target.value)}
            placeholder="检索任务名称、描述或 ID"
            className="h-9 pl-8"
          />
        </div>
        <div className="max-h-40 overflow-auto rounded border p-2">{taskListContent}</div>
      </div>
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel}>
          取消
        </Button>
        <Button disabled={saving} onClick={() => onSave(draft)}>
          {saving && <Spinner data-icon="inline-start" />}
          保存计划
        </Button>
      </div>
    </div>
  );
}

// 宽表响应式列存活（approval-records 同款机制）：展开行 colSpan 用 matchMedia
// 与表头可见列数保持同步，否则展开行会撕裂列网格。
const scheduleBreakpoints = ["(min-width: 48rem)", "(min-width: 64rem)", "(min-width: 80rem)"];

function subscribeScheduleColumns(onChange: () => void) {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return () => undefined;
  const queries = scheduleBreakpoints.map((query) => window.matchMedia(query));
  const offs = queries.map((query) => {
    const handler = () => onChange();
    query.addEventListener("change", handler);
    return () => query.removeEventListener("change", handler);
  });
  return () => {
    for (const off of offs) off();
  };
}

function scheduleColumnCount() {
  // 常驻 5 列（勾选/ID/名称/状态/操作）+ md:运行周期 + lg:时间线/绑定任务
  // + xl:备注/开始/结束/运行次数。
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return 6;
  const [md, lg, xl] = scheduleBreakpoints.map((query) => window.matchMedia(query).matches);
  return 5 + Number(md) + 2 * Number(lg) + 4 * Number(xl);
}

function TableSkeleton() {
  return (
    <div className="flex flex-col gap-3 px-4 py-2">
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-12 w-full" />
      <Skeleton className="h-12 w-full" />
      <Skeleton className="h-12 w-full" />
      <Skeleton className="h-12 w-full" />
    </div>
  );
}

export default function SchedulesPage() {
  const { periodLabel, startLabel, endLabel, timezoneLabel, nextWindowLabel, formatTime, statusText } =
    scheduleDisplay();
  const [items, setItems] = React.useState<TaskSchedule[]>([]);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [editing, setEditing] = React.useState<{ id?: number; value: ScheduleInput } | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);
  const [selectedIds, setSelectedIds] = React.useState<number[]>([]);
  const [expandedId, setExpandedId] = React.useState<number | null>(null);
  const [timelineById, setTimelineById] = React.useState<Record<number, TaskSchedule>>({});
  const [timelineLoadingId, setTimelineLoadingId] = React.useState<number | null>(null);
  const [columns, setColumns] = React.useState(6);
  React.useEffect(() => {
    const sync = () => setColumns(scheduleColumnCount());
    sync();
    return subscribeScheduleColumns(sync);
  }, []);
  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [s, t] = await Promise.all([api.schedules(), api.tasks()]);
      setItems(s);
      setTasks(t.tasks);
    } catch (e) {
      toast.error(`加载计划失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);
  const normalizedQuery = query.trim().toLowerCase();
  const filteredItems = !normalizedQuery
    ? items
    : items.filter((item) => {
        const display = scheduleDisplay();
        return [item.name, String(item.id), display.periodLabel(item), display.windowLabel(item), ...item.task_ids.map(String)]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
      });
  const totalPages = Math.max(1, Math.ceil(filteredItems.length / pageSize));
  const visibleItems = filteredItems.slice((page - 1) * pageSize, page * pageSize);
  const visibleIds = visibleItems.map((item) => item.id);
  const selectedVisibleCount = visibleIds.filter((id) => selectedIds.includes(id)).length;
  const allVisibleSelected = visibleItems.length > 0 && selectedVisibleCount === visibleItems.length;
  const someVisibleSelected = selectedVisibleCount > 0 && !allVisibleSelected;
  let headerSelectionState: boolean | "indeterminate" = false;
  if (allVisibleSelected) headerSelectionState = true;
  else if (someVisibleSelected) headerSelectionState = "indeterminate";
  const updateQuery = (value: string) => {
    setQuery(value);
    setPage(1);
  };
  const toggleSelected = (id: number, checked: boolean) => {
    setSelectedIds((current) => {
      if (!checked) return current.filter((selected) => selected !== id);
      return current.includes(id) ? current : [...current, id];
    });
  };
  const toggleAllVisible = (checked: boolean) => {
    setSelectedIds((current) => {
      if (checked) return Array.from(new Set([...current, ...visibleIds]));
      return current.filter((id) => !visibleIds.includes(id));
    });
  };
  const refreshTimeline = async (id: number) => {
    setTimelineLoadingId(id);
    try {
      const detail = await api.schedule(id);
      setTimelineById((current) => ({ ...current, [id]: detail }));
    } catch (e) {
      toast.error(`加载时间线失败：${(e as Error).message}`);
    } finally {
      setTimelineLoadingId(null);
    }
  };
  const invalidateTimeline = async (id: number) => {
    setTimelineById((current) => {
      if (!current[id]) return current;
      const next = { ...current };
      delete next[id];
      return next;
    });
    if (expandedId === id) await refreshTimeline(id);
  };
  const toggleTimeline = async (id: number) => {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(id);
    if (timelineById[id]) return;
    await refreshTimeline(id);
  };
  const save = async (value: ScheduleInput) => {
    if (
      !value.name.trim() ||
      !value.start_time ||
      (value.schedule_type === "once" ? !value.run_date : !value.weekdays?.length)
    ) {
      toast.error("请补全计划名称、日期/星期和开始时间");
      return;
    }
    setSaving(true);
    try {
      if (editing?.id) await api.updateSchedule(editing.id, value);
      else await api.createSchedule(value);
      toast.success("计划已保存");
      setEditing(null);
      await load();
    } catch (e) {
      toast.error(`保存计划失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };
  const remove = async (id: number) => {
    try {
      await api.deleteSchedule(id);
      setTimelineById((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
      if (expandedId === id) setExpandedId(null);
      await load();
    } catch (e) {
      toast.error(`删除计划失败：${(e as Error).message}`);
    }
  };
  const action = async (id: number, type: "pause" | "resume" | "run") => {
    try {
      if (type === "pause") await api.pauseSchedule(id);
      else if (type === "resume") await api.resumeSchedule(id);
      else {
        const result = await api.runScheduleNow(id);
        if (result.errors?.length) {
          toast.warning(
            `已启动 ${result.started} 个任务，但有 ${result.errors.length} 个任务未启动：${result.errors.join("; ")}`,
          );
        } else {
          toast.success(`已立即运行 ${result.started} 个任务`);
        }
      }
      await invalidateTimeline(id);
      await load();
    } catch (e) {
      toast.error(`操作失败：${(e as Error).message}`);
    }
  };
  const bulkRun = async () => {
    const ids = [...selectedIds];
    if (!ids.length) return;
    let started = 0;
    const errors: string[] = [];
    const results = await Promise.allSettled(ids.map((id) => api.runScheduleNow(id)));
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        errors.push(`计划 #${ids[index]}：${(result.reason as Error).message}`);
        return;
      }
      started += result.value.started;
      if (result.value.errors?.length) errors.push(`计划 #${ids[index]}：${result.value.errors.join("; ")}`);
    });
    if (errors.length) {
      toast.warning(`已启动 ${started} 个任务，但有 ${errors.length} 项未完成：${errors.join("; ")}`);
    } else {
      toast.success(`已立即运行 ${started} 个任务`);
    }
    setSelectedIds([]);
    await Promise.all(ids.map((id) => invalidateTimeline(id)));
    await load();
  };
  const bulkRemove = async () => {
    const ids = [...selectedIds];
    if (!ids.length) return;
    const results = await Promise.allSettled(ids.map((id) => api.deleteSchedule(id)));
    const failed = results.filter((result) => result.status === "rejected").length;
    if (failed) toast.warning(`已删除 ${ids.length - failed} 个计划，${failed} 个计划删除失败`);
    else toast.success(`已删除 ${ids.length} 个计划`);
    setTimelineById((current) => {
      const next = { ...current };
      ids.forEach((id) => {
        delete next[id];
      });
      return next;
    });
    if (expandedId && ids.includes(expandedId)) setExpandedId(null);
    setSelectedIds([]);
    await load();
  };
  let scheduleContent: React.ReactNode;
  if (loading) {
    scheduleContent = <TableSkeleton />;
  } else if (items.length === 0) {
    scheduleContent = (
      <Empty className="py-20">
        <EmptyHeader>
          <EmptyTitle>暂无计划任务</EmptyTitle>
          <EmptyDescription>点击右上角「新建计划」开始。</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  } else {
    scheduleContent = (
      <div className="grid gap-3">
        <div className="flex items-center justify-between gap-3">
          <div className="relative min-w-0 flex-1 sm:max-w-md">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(event) => updateQuery(event.target.value)}
              placeholder="检索计划名称、计划 ID 或任务 ID"
              className="h-9 pl-8"
            />
          </div>
          {selectedIds.length ? (
            <div className="flex flex-wrap items-center justify-end gap-2">
              <span className="text-muted-foreground text-sm">已选 {selectedIds.length} 个计划</span>
              <Button size="sm" variant="outline" onClick={() => void bulkRun()}>
                <Zap data-icon="inline-start" />
                立即运行
              </Button>
              <ConfirmDialog
                title="删除选中的计划"
                description={`将删除选中的 ${selectedIds.length} 个计划及其运行记录，绑定关系一并移除，此操作不可撤销。`}
                confirmText="确认删除"
                trigger={
                  <Button size="sm" variant="destructive">
                    <Trash2 data-icon="inline-start" />
                    删除
                  </Button>
                }
                onConfirm={bulkRemove}
              />
              <Button size="sm" variant="ghost" onClick={() => setSelectedIds([])}>
                清空选择
              </Button>
            </div>
          ) : null}
        </div>
        {filteredItems.length === 0 ? (
          <Empty className="py-20">
            <EmptyHeader>
              <EmptyTitle>没有匹配的计划任务</EmptyTitle>
              <EmptyDescription>调整搜索条件后重试。</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <>
            <div className="overflow-x-auto rounded-xl border bg-card">
              <Table className="table-fixed **:data-[slot='table-cell']:px-4 **:data-[slot='table-head']:px-4">
                <TableHeader className="bg-muted/40">
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        aria-label="选择当前页计划"
                        checked={headerSelectionState}
                        onCheckedChange={(checked) => toggleAllVisible(checked === true)}
                      />
                    </TableHead>
                    <TableHead className="w-16 font-mono">ID</TableHead>
                    <TableHead>计划名称</TableHead>
                    <TableHead className="hidden xl:table-cell w-px">备注</TableHead>
                    <TableHead className="hidden lg:table-cell w-24">时间线</TableHead>
                    <TableHead className="hidden md:table-cell min-w-44">运行周期</TableHead>
                    <TableHead className="hidden xl:table-cell min-w-36">开始时间</TableHead>
                    <TableHead className="hidden xl:table-cell min-w-36">结束时间</TableHead>
                    <TableHead className="hidden xl:table-cell min-w-20 text-center">运行次数</TableHead>
                    <TableHead className="hidden lg:table-cell min-w-32">绑定任务</TableHead>
                    <TableHead className="min-w-28">状态</TableHead>
                    <TableHead className="min-w-64 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleItems.map((item) => (
                    <React.Fragment key={item.id}>
                      <TableRow className="group">
                        <TableCell className="w-10">
                          <Checkbox
                            aria-label={`选择计划 ${item.name}`}
                            checked={selectedIds.includes(item.id)}
                            onCheckedChange={(checked) => toggleSelected(item.id, checked === true)}
                          />
                        </TableCell>
                        <TableCell>
                          <code className="bg-muted rounded px-1.5 py-0.5 font-mono text-xs tabular-nums">{item.id}</code>
                        </TableCell>
                        <TableCell className="font-medium">
                          <ScheduleNameEditor
                            value={item.name}
                            label={`计划 #${item.id}`}
                            onSave={async (name) => {
                              const updated = await api.renameSchedule(item.id, name);
                              setItems((current) =>
                                current.map((entry) => (entry.id === item.id ? { ...entry, name: updated.name } : entry)),
                              );
                            }}
                          />
                        </TableCell>
                        <TableCell className="hidden xl:table-cell">
                          <RemarkEditor
                            value={item.remark}
                            label={`计划 #${item.id} ${item.name}`}
                            onSave={async (remark) => {
                              const updated = await api.updateScheduleRemark(item.id, remark);
                              setItems((current) =>
                                current.map((entry) =>
                                  entry.id === item.id ? { ...entry, remark: updated.remark } : entry,
                                ),
                              );
                            }}
                          />
                        </TableCell>
                        <TableCell className="hidden lg:table-cell">
                          <Button size="sm" variant="outline" onClick={() => void toggleTimeline(item.id)}>
                            {expandedId === item.id ? (
                              <ChevronDown data-icon="inline-start" />
                            ) : (
                              <ChevronRight data-icon="inline-start" />
                            )}
                            {expandedId === item.id ? "收起" : "查看"}
                          </Button>
                        </TableCell>
                        <TableCell className="hidden text-sm md:table-cell">{periodLabel(item)}</TableCell>
                        <TableCell className="hidden xl:table-cell whitespace-nowrap text-sm">
                          {startLabel(item)}
                          {item.next_start ? (
                            <div className="mt-1 text-muted-foreground text-xs">
                              下次：{nextWindowLabel(item.next_start, item.timezone)}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell className="hidden xl:table-cell whitespace-nowrap text-sm">
                          {endLabel(item)}
                          {item.next_end ? (
                            <div className="mt-1 text-muted-foreground text-xs">
                              下次：{nextWindowLabel(item.next_end, item.timezone)}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell className="hidden xl:table-cell text-center text-sm tabular-nums">
                          {item.run_count ?? 0}
                          {item.last_run_at ? (
                            <div className="mt-1 text-muted-foreground text-xs">最近 {formatTime(item.last_run_at)}</div>
                          ) : null}
                        </TableCell>
                        <TableCell
                          className="hidden max-w-40 truncate text-sm lg:table-cell"
                          title={item.task_ids.map((id) => `#${id}`).join(", ")}
                        >
                          {item.task_ids.length ? item.task_ids.map((id) => `#${id}`).join(", ") : "无"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={statusClass(item.status)}>
                            {statusText(item)}
                          </Badge>
                          <div className="mt-1 text-muted-foreground text-xs">{timezoneLabel(item)}</div>
                          <div className="mt-1 text-muted-foreground text-xs">
                            最近：{formatTime(item.last_transition_at ?? undefined)}
                          </div>
                          {item.last_error ? (
                            <div className="mt-1 max-w-36 truncate text-destructive text-xs" title={item.last_error}>
                              {item.last_error}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                setEditing({
                                  id: item.id,
                                  value: {
                                    name: item.name,
                                    enabled: item.enabled,
                                    timezone_mode: item.timezone_mode,
                                    schedule_type: item.schedule_type,
                                    run_date: item.run_date,
                                    end_date: item.end_date,
                                    weekdays: item.weekdays,
                                    start_time: item.start_time.slice(0, 5),
                                    end_time: item.end_time?.slice(0, 5),
                                    start_immediately: item.start_immediately,
                                    task_ids: item.task_ids,
                                  },
                                })
                              }
                            >
                              编辑
                            </Button>
                            {item.enabled ? (
                              <Button size="sm" variant="outline" onClick={() => void action(item.id, "pause")}>
                                暂停
                              </Button>
                            ) : (
                              <Button size="sm" variant="outline" onClick={() => void action(item.id, "resume")}>
                                启用
                              </Button>
                            )}
                            <Button size="sm" variant="outline" onClick={() => void action(item.id, "run")}>
                              <Zap data-icon="inline-start" />
                              立即运行
                            </Button>
                            <ConfirmDialog
                              title="删除计划"
                              description={`将删除计划「${item.name}」及其运行记录，绑定关系一并移除，此操作不可撤销。`}
                              confirmText="确认删除"
                              trigger={
                                <Button size="sm" variant="ghost">
                                  <Trash2 data-icon="inline-start" />
                                  删除
                                </Button>
                              }
                              onConfirm={() => remove(item.id)}
                            />
                          </div>
                        </TableCell>
                      </TableRow>
                      {expandedId === item.id ? (
                        <TableRow>
                          <TableCell colSpan={columns} className="bg-muted/10 p-3">
                            <ScheduleTimeline schedule={timelineById[item.id]} loading={timelineLoadingId === item.id} />
                          </TableCell>
                        </TableRow>
                      ) : null}
                    </React.Fragment>
                  ))}
                </TableBody>
              </Table>
            </div>
            <TablePagination
              page={page}
              pageSize={pageSize}
              total={filteredItems.length}
              onPageChange={setPage}
              onPageSizeChange={(nextSize) => {
                setPageSize(nextSize);
                setPage(1);
              }}
            />
          </>
        )}
      </div>
    );
  }
  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="flex items-center gap-2 font-semibold text-2xl tracking-tight">
          <CalendarClock />
          计划任务
        </h1>
        <Button onClick={() => setEditing({ value: { ...blank, task_ids: [] } })}>
          <Plus data-icon="inline-start" />
          新建计划
        </Button>
      </div>
      {editing && (
        <Card>
          <CardHeader>
            <CardTitle>{editing.id ? "编辑计划" : "新建计划"}</CardTitle>
          </CardHeader>
          <CardContent>
            <ScheduleForm
              value={editing.value}
              tasks={tasks}
              saving={saving}
              onCancel={() => setEditing(null)}
              onSave={save}
            />
          </CardContent>
        </Card>
      )}
      {scheduleContent}
    </div>
  );
}
