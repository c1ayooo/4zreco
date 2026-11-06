"use client";
"use no memo";

import * as React from "react";

import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  type NodeProps,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge as RFEdge,
  type Node as RFNode,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { Bug, Compass, Flag, FlaskConical, Layers, Lightbulb, type LucideIcon, Target } from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { type Tone, toneClasses } from "@/lib/status";
import type { Edge, ExploreKind, TaskNode } from "@/lib/types";
import { cn } from "@/lib/utils";

export const relLabel: Record<string, string> = {
  spawns: "派生",
  derived_from: "意图链",
  yields: "产出",
  proves: "证明",
};

export const relColor: Record<string, string> = {
  spawns: "#10b981",
  derived_from: "#6366f1",
  yields: "#f59e0b",
  proves: "#ef4444",
};

type TypeMeta = {
  label: string;
  icon: LucideIcon;
  // DOM 徽标/图例用 chart-1..5 底章惯例（§5.1 分类色）；hex 仅供 MiniMap/画布字面渲染（§5.1 例外）。
  iconBg: string;
  hex: string;
};

const typeMeta: Record<ExploreKind, TypeMeta> = {
  task: {
    label: "根任务",
    icon: Flag,
    iconBg: "bg-chart-1/15 text-chart-1",
    hex: "#64748b",
  },
  begin: {
    label: "起点",
    icon: Flag,
    iconBg: "bg-chart-1/15 text-chart-1",
    hex: "#64748b",
  },
  goal: {
    label: "目标",
    icon: Target,
    iconBg: "bg-chart-2/15 text-chart-2",
    hex: "#10b981",
  },
  hint: {
    label: "提示",
    icon: Lightbulb,
    iconBg: "bg-chart-1/15 text-chart-1",
    hex: "#8b5cf6",
  },
  intent: {
    label: "意图",
    icon: Compass,
    iconBg: "bg-chart-3/15 text-chart-3",
    hex: "#3b82f6",
  },
  fact: {
    label: "事实",
    icon: FlaskConical,
    iconBg: "bg-chart-4/15 text-chart-4",
    hex: "#f59e0b",
  },
  finding: {
    label: "漏洞",
    icon: Bug,
    iconBg: "bg-chart-5/15 text-chart-5",
    hex: "#f43f5e",
  },
  digest: {
    label: "压缩",
    icon: Layers,
    iconBg: "bg-chart-2/15 text-chart-2",
    hex: "#14b8a6",
  },
};

// The task root is an origin fact (kind='fact', state='origin'); render it as "起点".
function viewKind(n: TaskNode): ExploreKind {
  return n.type === "fact" && n.state === "origin" ? "begin" : n.type;
}

function prioTone(p: number): Tone {
  return p >= 8 ? "red" : p >= 5 ? "amber" : "slate";
}

const summaryFields: Record<ExploreKind, string[]> = {
  task: ["summary", "description"],
  begin: ["summary", "description"],
  goal: ["text"],
  hint: [],
  intent: ["summary"],
  fact: ["summary"],
  finding: ["name", "summary"],
  digest: ["body"],
};

function nodeSummary(n: TaskNode): string {
  const raw = n.payload ?? "";
  const fields = summaryFields[viewKind(n)] ?? [];
  if (fields.length && raw.trim()) {
    try {
      const obj: unknown = JSON.parse(raw);
      if (obj && typeof obj === "object") {
        for (const f of fields) {
          const v = (obj as Record<string, unknown>)[f];
          if (typeof v === "string" && v.trim()) return v;
        }
      }
    } catch {
      /* 非 JSON：原样显示 */
    }
  }
  return raw;
}

// digestMemberIds reads the fact/intent ids a digest folds from its payload
// (member_ids.{facts,intents}); ids are numbers in JSON, node ids are strings.
function digestMemberIds(n: TaskNode): string[] {
  if (n.type !== "digest" || !n.payload) return [];
  try {
    const p = JSON.parse(n.payload) as {
      member_ids?: { facts?: Array<string | number>; intents?: Array<string | number> };
    };
    return [...(p.member_ids?.facts ?? []), ...(p.member_ids?.intents ?? [])].map(String);
  } catch {
    return [];
  }
}

// collapseDigestGraph contracts each active digest's covered members into the
// digest super-node: the members are dropped from the rendered set and every
// edge touching a member is rewired onto its digest (member→member internal
// edges collapse to a self-loop and are dropped; the resulting edges are
// deduped by src+rel+dst). covers edges are structural and never drawn.
// Superseded digests (no covers edges) are dropped entirely. A graph with no
// active digest passes through unchanged. The full node list is kept by the
// caller so the detail drawer can still resolve a folded member by id.
function collapseDigestGraph(nodes: TaskNode[], edges: Edge[]): { viewNodes: TaskNode[]; viewEdges: Edge[] } {
  const activeDigests = new Set(nodes.filter((n) => n.type === "digest" && n.state === "active").map((n) => n.id));
  const memberToDigest = new Map<string, string>();
  for (const e of edges) {
    if (e.rel === "covers" && activeDigests.has(e.src)) memberToDigest.set(e.dst, e.src);
  }
  const viewNodes = nodes.filter((n) => (n.type === "digest" ? n.state === "active" : !memberToDigest.has(n.id)));
  const remap = (id: string) => memberToDigest.get(id) ?? id;
  const seen = new Set<string>();
  const rewired: Edge[] = [];
  // src+dst of every rewired yields edge, so the inverse derived_from can be dropped.
  const produced = new Set<string>();
  for (const e of edges) {
    if (e.rel === "covers") continue;
    const src = remap(e.src);
    const dst = remap(e.dst);
    if (src === dst) continue;
    const key = `${src}\u0000${e.rel}\u0000${dst}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (e.rel === "yields") produced.add(`${src} ${dst}`);
    rewired.push(src === e.src && dst === e.dst ? e : { ...e, src, dst });
  }
  // yields(A→B) and derived_from(B→A) are inverse relations: a finding is
  // yielded by one intent but derived_from other intents, so the raw graph has
  // no 2-cycle. Folding those distinct intents into one digest collapses both
  // onto the digest↔member pair, leaving a redundant reverse edge the layered
  // layout draws as an overlapping back-edge. Drop each derived_from whose
  // reverse yields exists, keeping the production direction (→member).
  const viewEdges = rewired.filter((e) => !(e.rel === "derived_from" && produced.has(`${e.dst} ${e.src}`)));
  return { viewNodes, viewEdges };
}

const COL_W = 360;
const ROW_H = 140;

type ExploreNodeData = { node: TaskNode };
type ExploreRFNode = RFNode<ExploreNodeData, "explore">;

function pushMap(m: Map<string, string[]>, k: string, v: string) {
  const a = m.get(k);
  if (a) a.push(v);
  else m.set(k, [v]);
}

// computeLayout auto-layers nodes by longest path along edges (cycle-safe DFS
// break + barycenter ordering), so origin → … → finding reads left-to-right.
function computeLayout(nodes: TaskNode[], edges: Edge[]): Map<string, { x: number; y: number }> {
  const order = nodes.map((n) => n.id);
  const idset = new Set(order);
  const valid = edges.filter((e) => idset.has(e.src) && idset.has(e.dst));
  const key = (s: string, d: string) => `${s}->${d}`;

  const out = new Map<string, string[]>();
  for (const e of valid) pushMap(out, e.src, e.dst);

  const seen = new Map<string, 0 | 1 | 2>();
  const back = new Set<string>();
  for (const root of order) {
    if ((seen.get(root) ?? 0) !== 0) continue;
    const stack: Array<{ u: string; i: number }> = [{ u: root, i: 0 }];
    seen.set(root, 1);
    while (stack.length) {
      const top = stack[stack.length - 1];
      const nbrs = out.get(top.u) ?? [];
      if (top.i >= nbrs.length) {
        seen.set(top.u, 2);
        stack.pop();
        continue;
      }
      const v = nbrs[top.i++];
      const s = seen.get(v) ?? 0;
      if (s === 1) back.add(key(top.u, v));
      else if (s === 0) {
        seen.set(v, 1);
        stack.push({ u: v, i: 0 });
      }
    }
  }

  const dagSucc = new Map<string, string[]>();
  const indeg = new Map<string, number>(order.map((id) => [id, 0]));
  for (const e of valid) {
    if (back.has(key(e.src, e.dst))) continue;
    pushMap(dagSucc, e.src, e.dst);
    indeg.set(e.dst, (indeg.get(e.dst) ?? 0) + 1);
  }
  const layer = new Map<string, number>(order.map((id) => [id, 0]));
  const queue = order.filter((id) => (indeg.get(id) ?? 0) === 0);
  for (let qi = 0; qi < queue.length; qi++) {
    const u = queue[qi];
    for (const v of dagSucc.get(u) ?? []) {
      layer.set(v, Math.max(layer.get(v) ?? 0, (layer.get(u) ?? 0) + 1));
      const d = (indeg.get(v) ?? 0) - 1;
      indeg.set(v, d);
      if (d === 0) queue.push(v);
    }
  }

  const maxLayer = Math.max(0, ...layer.values());
  const columns: string[][] = Array.from({ length: maxLayer + 1 }, () => []);
  for (const id of order) columns[layer.get(id) ?? 0].push(id);

  const colIndexOf = new Map<string, number>();
  columns.forEach((ids, c) => ids.forEach((id) => colIndexOf.set(id, c)));
  const neighbors = new Map<string, string[]>();
  for (const e of valid) {
    const cs = colIndexOf.get(e.src);
    const cd = colIndexOf.get(e.dst);
    if (cs === undefined || cd === undefined || Math.abs(cs - cd) !== 1) continue;
    pushMap(neighbors, e.src, e.dst);
    pushMap(neighbors, e.dst, e.src);
  }
  const sweep = (dir: 1 | -1) => {
    const start = dir === 1 ? 1 : columns.length - 2;
    const end = dir === 1 ? columns.length : -1;
    for (let c = start; c !== end; c += dir) {
      const ref = c - dir;
      const refIndex = new Map(columns[ref].map((id, i) => [id, i]));
      const scored = columns[c].map((id, i) => {
        const ns = (neighbors.get(id) ?? [])
          .map((nid) => refIndex.get(nid))
          .filter((v): v is number => v !== undefined);
        const bary = ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : i;
        return { id, bary, i };
      });
      scored.sort((a, b) => a.bary - b.bary || a.i - b.i);
      columns[c] = scored.map((s) => s.id);
    }
  };
  for (let iter = 0; iter < 4; iter++) {
    sweep(1);
    sweep(-1);
  }

  const maxCount = Math.max(1, ...columns.map((c) => c.length));
  const midline = ((maxCount - 1) * ROW_H) / 2;
  const pos = new Map<string, { x: number; y: number }>();
  columns.forEach((ids, c) => {
    const startY = midline - ((ids.length - 1) * ROW_H) / 2;
    ids.forEach((id, i) => pos.set(id, { x: c * COL_W, y: startY + i * ROW_H }));
  });
  return pos;
}

// Dify-style node card.
function ExploreNode({ data, selected }: NodeProps<ExploreRFNode>) {
  const n = data.node;
  const kind = viewKind(n);
  const meta = typeMeta[kind] ?? typeMeta.intent;
  const Icon = meta.icon;
  const showState = n.type === "goal" || n.type === "intent";
  const showPriority = (n.type === "goal" || n.type === "intent") && n.priority > 0;
  const isLive = !n.inherited && n.type === "intent" && n.state === "running";

  return (
    <div
      className={cn(
        "w-[240px] cursor-pointer rounded-2xl border-2 transition-colors",
        selected ? "border-ring" : isLive ? "border-primary/50" : "border-transparent",
      )}
    >
      <div className="group relative rounded-[14px] border border-border bg-card shadow-sm transition-shadow hover:shadow-lg">
        <Handle
          type="target"
          position={Position.Left}
          className="!size-2 !border-2 !border-border !bg-card opacity-0 transition-opacity group-hover:opacity-100"
        />
        <div className="flex items-center gap-2 px-3 pt-3 pb-1.5">
          <span className={cn("flex size-6 shrink-0 items-center justify-center rounded-lg shadow-sm", meta.iconBg)}>
            <Icon className="size-3.5" />
          </span>
          <span className="grow truncate font-semibold text-foreground text-sm">{meta.label}</span>
          {isLive && <span className="size-2 shrink-0 animate-pulse rounded-full bg-info" />}
          {showPriority && (
            <span
              className={cn(
                "shrink-0 rounded-md px-1.5 py-0.5 font-semibold text-xs tabular-nums",
                toneClasses[prioTone(n.priority)],
              )}
            >
              P{n.priority}
            </span>
          )}
        </div>
        <div className="line-clamp-3 px-3 pb-2 text-muted-foreground text-sm leading-snug">
          {nodeSummary(n) || meta.label}
        </div>
        <div className="flex items-center justify-between gap-2 px-3 pb-2.5">
          {n.inherited && n.source_task_id ? (
            <Badge variant="outline" className="max-w-32 truncate" title={`继承自任务 #${n.source_task_id}，只读`}>
              来源 #{n.source_task_id}
            </Badge>
          ) : showState ? (
            <StatusBadge
              domain={n.type === "goal" ? "goal" : "intent"}
              value={n.state}
              dot
              className="px-1.5 py-0 text-xs"
              title={n.blocked_reason}
            />
          ) : (
            <span className="text-muted-foreground text-xs">{meta.label}</span>
          )}
          <span className="shrink-0 font-mono text-muted-foreground text-xs">#{n.id}</span>
        </div>
        <Handle
          type="source"
          position={Position.Right}
          className="!size-2 !border-2 !border-border !bg-card opacity-0 transition-opacity group-hover:opacity-100"
        />
      </div>
    </div>
  );
}

const nodeTypes = { explore: ExploreNode };

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 py-1.5 text-sm">
      <span className="w-14 shrink-0 text-muted-foreground">{label}</span>
      <span className="min-w-0 flex-1 break-words text-foreground">{children}</span>
    </div>
  );
}

function NodeDetailSheet({
  node,
  nodesById,
  onSelect,
  onOpenChange,
}: {
  node: TaskNode | null;
  nodesById: Map<string, TaskNode>;
  onSelect: (n: TaskNode) => void;
  onOpenChange: (open: boolean) => void;
}) {
  const meta = node ? (typeMeta[viewKind(node)] ?? typeMeta.intent) : null;
  const Icon = meta?.icon;
  const raw = node ? JSON.stringify(node, null, 2) : "";
  const memberIds = node ? digestMemberIds(node) : [];
  const members = memberIds.map((id) => nodesById.get(id)).filter((m): m is TaskNode => !!m);

  return (
    <Sheet open={node !== null} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 p-0 data-[side=right]:sm:max-w-md">
        {node && meta && Icon && (
          <>
            <SheetHeader className="border-b p-4">
              <div className="flex items-center gap-2.5 pr-8">
                <span
                  className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg shadow-sm", meta.iconBg)}
                >
                  <Icon className="size-4" />
                </span>
                <div className="min-w-0">
                  <SheetTitle className="leading-tight">{meta.label}</SheetTitle>
                  <span className="font-mono text-muted-foreground text-xs">{node.id}</span>
                </div>
                {node.inherited && node.source_task_id && (
                  <Badge variant="outline" className="ml-auto shrink-0">
                    来源任务 #{node.source_task_id} · 只读
                  </Badge>
                )}
              </div>
            </SheetHeader>

            <ScrollArea className="min-h-0 flex-1">
              <div className="flex w-full min-w-0 flex-col gap-4 p-4">
                <section>
                  <h4 className="mb-1 font-medium text-muted-foreground text-xs">属性</h4>
                  <DetailRow label="类型">{meta.label}</DetailRow>
                  <DetailRow label="状态">
                    {node.type === "goal" || node.type === "intent" ? (
                      <StatusBadge
                        domain={node.type === "goal" ? "goal" : "intent"}
                        value={node.state}
                        dot
                        className="px-1.5 py-0 text-xs"
                      />
                    ) : (
                      <span className="font-mono text-xs">{node.state}</span>
                    )}
                  </DetailRow>
                  {node.blocked_reason && (
                    <DetailRow label="中断原因">
                      <span className="text-muted-foreground text-xs">{node.blocked_reason}</span>
                    </DetailRow>
                  )}
                  <DetailRow label="优先级">
                    <span className="tabular-nums">{node.priority}</span>
                  </DetailRow>
                  <DetailRow label="来源">
                    <span className="font-mono text-xs">{node.origin}</span>
                  </DetailRow>
                  {node.inherited && node.source_task_id && (
                    <DetailRow label="来源任务">
                      <span className="font-mono text-xs">#{node.source_task_id}（继承，只读）</span>
                    </DetailRow>
                  )}
                  <DetailRow label="时间">{new Date(node.ts).toLocaleString("zh-CN")}</DetailRow>
                </section>

                {node.type === "digest" && (
                  <>
                    {nodeSummary(node) && (
                      <section className="border-t pt-3">
                        <h4 className="mb-1.5 font-medium text-muted-foreground text-xs">压缩结论</h4>
                        <p className="whitespace-pre-wrap break-words text-foreground text-sm leading-relaxed">
                          {nodeSummary(node)}
                        </p>
                      </section>
                    )}
                    <section className="border-t pt-3">
                      <h4 className="mb-1.5 font-medium text-muted-foreground text-xs">
                        压缩的节点（{memberIds.length}）
                      </h4>
                      <div className="flex flex-col gap-1.5">
                        {members.map((m) => {
                          const mMeta = typeMeta[viewKind(m)] ?? typeMeta.intent;
                          const MIcon = mMeta.icon;
                          return (
                            <button
                              key={m.id}
                              type="button"
                              onClick={() => onSelect(m)}
                              className="flex items-start gap-2 rounded-md border p-2 text-left transition-colors hover:bg-accent"
                            >
                              <span
                                className={cn(
                                  "mt-0.5 flex size-5 shrink-0 items-center justify-center rounded",
                                  mMeta.iconBg,
                                )}
                              >
                                <MIcon className="size-3" />
                              </span>
                              <span className="min-w-0 flex-1">
                                <span className="line-clamp-2 text-foreground text-xs leading-snug">
                                  {nodeSummary(m) || mMeta.label}
                                </span>
                                <span className="block font-mono text-muted-foreground text-xs">
                                  {mMeta.label} · #{m.id}
                                </span>
                              </span>
                            </button>
                          );
                        })}
                        {members.length < memberIds.length && (
                          <span className="text-muted-foreground text-xs">
                            另有 {memberIds.length - members.length} 个成员节点未随当前图加载
                          </span>
                        )}
                      </div>
                    </section>
                  </>
                )}

                <section className="border-t pt-3">
                  <div className="mb-1.5 flex items-center justify-between">
                    <h4 className="font-medium text-muted-foreground text-xs">原始数据</h4>
                    <CopyButton text={raw} size="xs" variant="ghost" />
                  </div>
                  <pre className="max-w-full overflow-hidden whitespace-pre-wrap break-all rounded-md border bg-muted/50 p-3 font-mono text-foreground text-xs leading-relaxed">
                    {raw}
                  </pre>
                </section>
              </div>
            </ScrollArea>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

// ExplorationGraphInner renders the given nodes/edges as a React Flow canvas.
// Positions are auto-laid-out and preserved across prop updates (so a polling
// caller's graph doesn't jump); click a node to open its detail drawer.
function ExplorationGraphInner({
  nodes,
  edges,
  emptyHint = "暂无探索数据",
}: {
  nodes: TaskNode[];
  edges: Edge[];
  emptyHint?: string;
}) {
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<ExploreRFNode>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<RFEdge>([]);
  const [selected, setSelected] = React.useState<TaskNode | null>(null);
  // Full node index (incl. folded members) so the digest drawer can resolve
  // covered members even though they are not rendered on the canvas.
  const nodesById = React.useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  // Collapsed view: folded members removed, their edges rewired onto the digest.
  const { viewNodes, viewEdges } = React.useMemo(() => collapseDigestGraph(nodes, edges), [nodes, edges]);
  const isEmpty = viewNodes.length === 0;

  React.useEffect(() => {
    setSelected((cur) => (cur ? (nodesById.get(cur.id) ?? cur) : cur));
    const liveTargets = new Set(
      viewNodes.filter((n) => !n.inherited && n.type === "intent" && n.state === "running").map((n) => n.id),
    );
    const layout = computeLayout(viewNodes, viewEdges);
    setRfNodes((prev) => {
      const prevPos = new Map(prev.map((p) => [p.id, p.position]));
      return viewNodes.map((n) => ({
        id: n.id,
        type: "explore" as const,
        position: prevPos.get(n.id) ?? layout.get(n.id) ?? { x: 0, y: 0 },
        data: { node: n },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      }));
    });
    setRfEdges(
      viewEdges.map((e, i) => {
        const color = relColor[e.rel] ?? "#94a3b8";
        const animated = liveTargets.has(e.dst);
        return {
          id: `e${i}-${e.src}-${e.dst}`,
          source: e.src,
          target: e.dst,
          label: relLabel[e.rel] ?? e.rel,
          type: "default",
          animated,
          labelShowBg: false,
          labelStyle: { fontSize: 10, fontWeight: 600, fill: color },
          style: { stroke: color, strokeWidth: 2, strokeOpacity: animated ? 0.9 : 0.55 },
          markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        } satisfies RFEdge;
      }),
    );
  }, [viewNodes, viewEdges, nodesById, setRfNodes, setRfEdges]);

  return (
    <>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => setSelected(node.data.node)}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        proOptions={{ hideAttribution: true }}
        onlyRenderVisibleElements
        minZoom={0.1}
        className="!bg-background"
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} className="text-muted-foreground/40" />
        <Controls
          showInteractive={false}
          className="!rounded-lg !border !shadow-sm [&>button]:!border-border [&>button]:!bg-card [&>button:hover]:!bg-accent [&_svg]:!fill-foreground"
        />
        <MiniMap
          pannable
          zoomable
          className="!bg-card !rounded-lg !border !shadow-sm"
          maskColor="rgb(148 163 184 / 0.18)"
          nodeColor={(node) => {
            const data = node.data as ExploreNodeData | undefined;
            const k = data?.node ? viewKind(data.node) : "intent";
            return typeMeta[k]?.hex ?? "#94a3b8";
          }}
          nodeStrokeWidth={0}
          nodeBorderRadius={4}
        />
        <Panel position="top-left">
          <div className="flex flex-col gap-2.5 rounded-lg border bg-card/95 p-3 text-xs shadow-sm backdrop-blur">
            {isEmpty && <span className="text-muted-foreground">{emptyHint}</span>}
            <div className="flex flex-wrap gap-x-3 gap-y-1.5">
              {(["begin", "goal", "intent", "fact", "finding", "hint", "digest"] as ExploreKind[]).map((k) => {
                const m = typeMeta[k];
                const Icon = m.icon;
                return (
                  <span key={k} className="inline-flex items-center gap-1.5 text-foreground">
                    <span className={cn("flex size-4 items-center justify-center rounded", m.iconBg)}>
                      <Icon className="size-2.5 text-white" />
                    </span>
                    {m.label}
                  </span>
                );
              })}
            </div>
            <div className="flex flex-wrap gap-x-3 gap-y-1.5 border-border/60 border-t pt-2 text-muted-foreground">
              {Object.entries(relLabel).map(([k, v]) => (
                <span key={k} className="inline-flex items-center gap-1.5">
                  <span className="h-0.5 w-4 rounded-full" style={{ backgroundColor: relColor[k] }} />
                  {v}
                </span>
              ))}
            </div>
          </div>
        </Panel>
      </ReactFlow>
      <NodeDetailSheet
        node={selected}
        nodesById={nodesById}
        onSelect={setSelected}
        onOpenChange={(o) => !o && setSelected(null)}
      />
    </>
  );
}

// ExplorationGraph is the shared探索图/攻击链路图 canvas — used by the task graph
// tab (full graph, polled) and the finding lineage view (origin→finding subgraph).
export function ExplorationGraph({
  nodes,
  edges,
  className,
  emptyHint,
}: {
  nodes: TaskNode[];
  edges: Edge[];
  className?: string;
  emptyHint?: string;
}) {
  return (
    <div className={cn("w-full overflow-hidden rounded-xl", className)}>
      <ReactFlowProvider>
        <ExplorationGraphInner nodes={nodes} edges={edges} emptyHint={emptyHint} />
      </ReactFlowProvider>
    </div>
  );
}
