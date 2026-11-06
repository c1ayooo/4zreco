"use client";

import * as React from "react";

import { ExplorationGraph } from "@/components/exploration-graph";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Edge, TaskNode } from "@/lib/types";

// FindingLineageView renders the exploration sub-graph from the task's initial
// node down to this finding's node — the same 攻击链路图 canvas as the task graph,
// scoped to just this finding's lineage.
export function FindingLineageView({ findingId }: { findingId: string }) {
  const [nodes, setNodes] = React.useState<TaskNode[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [failed, setFailed] = React.useState(false);
  const [retry, setRetry] = React.useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: retry invalidates the lineage fetch without changing findingId.
  React.useEffect(() => {
    let alive = true;
    api
      .findingLineage(findingId)
      .then((g) => {
        if (!alive) return;
        setNodes(g.nodes ?? []);
        setEdges(g.edges ?? []);
        setFailed(false);
      })
      .catch(() => {
        if (alive) setFailed(true);
      })
      .finally(() => {
        if (alive) setLoaded(true);
      });
    return () => {
      alive = false;
    };
  }, [findingId, retry]);

  if (failed) {
    return (
      <div className="p-6">
        <Alert variant="destructive">
          <AlertDescription>
            <div className="flex flex-wrap items-center gap-2">
              <span>链路图加载失败</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setFailed(false);
                  setLoaded(false);
                  setRetry((v) => v + 1);
                }}
              >
                重试
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (loaded && nodes.length === 0) {
    return (
      <p className="p-6 text-muted-foreground text-sm">无链路可展示（该漏洞未关联探索节点，或所属任务已删除）。</p>
    );
  }

  return (
    <ExplorationGraph nodes={nodes} edges={edges} className="h-[68vh]" emptyHint={loaded ? "无链路" : "加载中…"} />
  );
}
