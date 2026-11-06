"use client";

import Link from "next/link";
import React from "react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Task } from "@/lib/types";

const POLL_MS = 5000;

// 头部「在跑任务」入口：有 running 任务时显示可点击入口直达任务详情，无则不占位。
// 5s 轮询任务列表（头部组件轻量，不接 SSE）。不放任务名——任务详情页头部已有，
// 重复展示两头维护；入口只承担「快速到达」。
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
  const title = `当前在跑的任务（${first.name?.trim() || first.description.trim().slice(0, 30) || `任务 ${first.id}`}），点击查看详情`;
  return (
    <Button
      asChild
      size="sm"
      variant="outline"
      className="h-7 gap-2 rounded-full px-3 font-normal text-muted-foreground"
    >
      <Link href={`/function/tasks/detail?id=${encodeURIComponent(first.id)}`} title={title}>
        <span className="relative flex size-2 shrink-0">
          <span className="absolute inline-flex size-2 animate-ping rounded-full bg-success opacity-60" />
          <span className="relative inline-flex size-2 rounded-full bg-success" />
        </span>
        在跑任务
        {running.length > 1 && (
          <span className="font-mono tabular-nums text-muted-foreground">×{running.length}</span>
        )}
      </Link>
    </Button>
  );
}
