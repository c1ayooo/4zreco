"use client";

import * as React from "react";

import Link from "next/link";

import { CheckIcon, ChevronDownIcon } from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { api } from "@/lib/api";
import type { Task } from "@/lib/types";
import { cn } from "@/lib/utils";

// 态势条里的任务标签口径与任务列表页一致：名称 > 描述前 30 字 > 任务 id。
function taskLabel(t: Task): string {
  return t.name?.trim() || t.description.trim().slice(0, 30) || `任务 ${t.id}`;
}

const detailHref = (id: string) => `/function/tasks/detail?id=${encodeURIComponent(id)}`;

// 在跑任务跳转入口：单任务直达详情；并行多任务时下拉逐个选择（带 ×N 计数）。
// 触发位展示全局 active 任务（Check 标记进菜单）；active 不在跑时回退到第一个在跑任务。
function RunningTaskEntry({ running, activeId }: { running: Task[]; activeId: string }) {
  const focusTask = running.find((t) => t.id === activeId) ?? running[0];
  if (!focusTask) return null;
  const pulseDot = <span className="size-1.5 shrink-0 animate-pulse rounded-full bg-success" />;
  if (running.length === 1) {
    return (
      <Link
        href={detailHref(focusTask.id)}
        className="flex min-w-0 flex-1 items-center gap-1.5 transition-colors hover:text-foreground"
      >
        {pulseDot}
        <span className="truncate text-foreground">{taskLabel(focusTask)}</span>
      </Link>
    );
  }
  const menuTasks = [...running].sort((a, b) => Number(b.id === activeId) - Number(a.id === activeId));
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="flex min-w-0 flex-1 cursor-pointer items-center gap-1.5 text-left transition-colors hover:text-foreground"
        >
          {pulseDot}
          <span className="truncate text-foreground">{taskLabel(focusTask)}</span>
          <span className="shrink-0 font-mono tabular-nums">×{running.length}</span>
          <ChevronDownIcon className="size-3 shrink-0" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-80">
        {menuTasks.map((t) => (
          <DropdownMenuItem key={t.id} asChild>
            <Link href={detailHref(t.id)}>
              {t.id === activeId && <CheckIcon className="text-primary" />}
              <span className="truncate">{taskLabel(t)}</span>
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// OpsPulse 全局态势条：顶栏下一行常驻的作业脉搏——运行中任务、待审批数、LLM 状态。
// 只让有内容的项发声（N=0 的待审批不渲染），保持 quiet；30s 轮询，出错静默保留旧值。
export function OpsPulse({ className }: { className?: string }) {
  const [running, setRunning] = React.useState<Task[]>([]);
  const [activeId, setActiveId] = React.useState("");
  const [known, setKnown] = React.useState(false);
  const [llm, setLlm] = React.useState<boolean | null>(null);
  const [interceptPending, setInterceptPending] = React.useState(0);

  React.useEffect(() => {
    let cancelled = false;
    async function load() {
      const [stats, intercept, tasks] = await Promise.allSettled([api.stats(), api.interceptPending(), api.tasks()]);
      if (cancelled) return;
      if (tasks.status === "fulfilled") {
        setRunning(tasks.value.tasks.filter((t) => t.status === "running"));
        setActiveId(tasks.value.active);
        setKnown(true);
      }
      if (stats.status === "fulfilled") setLlm(stats.value.llm_configured);
      setInterceptPending(intercept.status === "fulfilled" ? intercept.value.length : 0);
    }
    void load();
    const timer = setInterval(() => void load(), 30000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div
      className={cn(
        "mx-4 mt-2.5 flex h-9 shrink-0 items-center gap-4 overflow-hidden rounded-full border bg-card px-4 text-muted-foreground text-xs shadow-xs md:mx-6",
        className,
      )}
    >
      {known && running.length > 0 ? <RunningTaskEntry running={running} activeId={activeId} /> : null}
      {known && running.length === 0 ? (
        <span className="flex items-center gap-1.5">
          <span className="size-1.5 shrink-0 rounded-full bg-border" />
          空闲
        </span>
      ) : null}
      {interceptPending > 0 ? (
        <Link
          href="/system/intercept/approvals"
          className="flex shrink-0 items-center gap-1 whitespace-nowrap tabular-nums transition-colors hover:text-foreground"
        >
          拦截待审批 {interceptPending}
        </Link>
      ) : null}
      {llm != null && (
        <span className="ml-auto shrink-0 whitespace-nowrap tabular-nums">{llm ? "LLM 就绪" : "LLM 未配置"}</span>
      )}
    </div>
  );
}
