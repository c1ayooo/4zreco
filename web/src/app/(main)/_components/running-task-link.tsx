"use client";

import Link from "next/link";
import React from "react";

import { api } from "@/lib/api";
import type { Task } from "@/lib/types";

const POLL_MS = 5000;

// 头部「在跑任务」入口：有 running 任务时显示可点击胶囊直达任务详情，无则不占位。
// 5s 轮询任务列表（头部组件轻量，不接 SSE）。
export function RunningTaskLink() {
  const [running, setRunning] = React.useState<Task[]>([]);

  React.useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .tasks()
        .then((r) => {
          if (alive) setRunning(r.tasks.filter((t) => t.status === "running"));
        })
        .catch(() => {});
    void load();
    const timer = setInterval(load, POLL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  if (running.length === 0) return null;
  const first = running[0]!;
  const label = first.name?.trim() || first.description.trim().slice(0, 40) || `任务 ${first.id}`;
  return (
    <Link
      href={`/function/tasks/detail?id=${encodeURIComponent(first.id)}`}
      title={`当前在跑的任务，点击查看详情${running.length > 1 ? `（共 ${running.length} 个）` : ""}`}
      className="flex max-w-[28rem] items-center gap-2 rounded-full border bg-background/60 px-3 py-1 text-xs transition-colors hover:bg-accent"
    >
      <span className="relative flex size-2 shrink-0">
        <span className="absolute inline-flex size-2 animate-ping rounded-full bg-emerald-400 opacity-60" />
        <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
      </span>
      <span className="truncate text-muted-foreground">{label}</span>
      {running.length > 1 && (
        <span className="shrink-0 rounded-full bg-muted px-1.5 py-0.5 text-[10px] tabular-nums text-muted-foreground">
          +{running.length - 1}
        </span>
      )}
    </Link>
  );
}
