"use client";

import * as React from "react";

import { ExplorationGraph } from "@/components/exploration-graph";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { Edge, TaskNode } from "@/lib/types";

export function GraphTab({ taskId }: { taskId: string }) {
  const [nodes, setNodes] = React.useState<TaskNode[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);
  // 首帧加载与错误轻量态：空态由 ExplorationGraph 内置提示兜底。
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const [attempt, setAttempt] = React.useState(0);
  // 上一次图数据的签名:轮询拿到相同数据时跳过 setState,避免整图无谓重建(拖动时
  // 才不会被 20s 轮询打断而顿挫)。只取影响渲染的字段。
  const sigRef = React.useRef("");

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt invalidates the graph fetch without changing taskId.
  React.useEffect(() => {
    let cancelled = false;
    sigRef.current = ""; // 换任务:强制下一次刷新
    const load = () => {
      api
        .explorationGraph(taskId)
        .then((g) => {
          if (cancelled) return;
          const ns = g.nodes ?? [];
          const es = g.edges ?? [];
          const sig = JSON.stringify([
            ns.map((n) => [n.id, n.type, n.state, n.priority, n.payload]),
            es.map((e) => [e.src, e.dst, e.rel]),
          ]);
          if (sig === sigRef.current) return; // 无变化 → 不重建
          sigRef.current = sig;
          setNodes(ns);
          setEdges(es);
          setError("");
        })
        .catch((e) => {
          if (cancelled) return;
          // 轮询尽力而为:已有数据时保留旧图;首帧失败才亮错误态。
          setError((e as Error).message || "加载失败");
        })
        .finally(() => {
          if (!cancelled) setLoaded(true);
        });
    };
    load();
    const timer = setInterval(load, 20000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [taskId, attempt]);

  let content: React.ReactNode;
  if (!loaded) {
    content = <Skeleton className="h-[72vh] w-full rounded-none" />;
  } else if (error && nodes.length === 0) {
    content = (
      <div className="flex h-[72vh] items-center justify-center p-6">
        <Alert variant="destructive" className="max-w-sm">
          <AlertDescription>
            <div className="flex flex-wrap items-center gap-2">
              <span>探索图加载失败：{error}</span>
              <Button variant="outline" size="sm" onClick={() => setAttempt((v) => v + 1)}>
                重试
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      </div>
    );
  } else {
    content = <ExplorationGraph nodes={nodes} edges={edges} className="h-[72vh]" />;
  }

  return (
    <Card>
      <CardContent className="p-0">{content}</CardContent>
    </Card>
  );
}
