"use client";

// 任务详情「文件」标签（移植自 ARTEX 0.3.29 A5）：只读浏览任务工作目录
// （Data/tasks/<id>，agent 的 CWD）。树形逐层展开 + 最近文件两种视图；文本
// 内联预览（2MiB 上限，二进制/超大只给标志）、图片魔数校验预览、单文件下载
// 与目录 ZIP 导出。symlink 只标注不可打开。文案硬编码中文（本仓库无 i18n 层）。

import * as React from "react";

import { useRouter, useSearchParams } from "next/navigation";

import {
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  FileIcon,
  FolderIcon,
  RefreshCwIcon,
} from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { Task, TaskFileEntry, TaskFileListing, WorkspaceFile } from "@/lib/types";

function fileSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 ** 2).toFixed(1)} MiB`;
}
const isImage = (path: string) => /\.(png|jpe?g|webp|gif)$/i.test(path);

// 任务工作目录里的固定子目录给个可读别名；其余按原名显示。
const KNOWN_DIRS: Record<string, string> = {
  uploads: "上传附件",
  "cmd-output": "命令输出",
  artifacts: "任务产物",
};

export function FilesTab({ task, active }: { task: Task; active: boolean }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const requestedPath = searchParams.get("path") ?? "";
  const [mode, setMode] = React.useState<"tree" | "recent">("tree");
  const [listings, setListings] = React.useState<Record<string, TaskFileEntry[]>>({});
  const [expanded, setExpanded] = React.useState<string[]>([]);
  const [summary, setSummary] = React.useState<TaskFileListing | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [preview, setPreview] = React.useState<{ path: string; file?: WorkspaceFile; error?: string } | null>(null);
  const generation = React.useRef(0);
  const previewGeneration = React.useRef(0);

  const refresh = React.useCallback(async () => {
    const seq = ++generation.current;
    setLoading(true);
    try {
      const [all, ...dirs] = await Promise.all([
        api.taskFilesAll(task.id),
        ...["", ...expanded].map(async (path) => {
          try {
            return { path, result: await api.taskFiles(task.id, path) };
          } catch {
            // 子目录消失（运行中被清理）不算整体失败，根目录失败才算。
            if (path === "") throw new Error("任务文件不可用");
            return { path, result: null };
          }
        }),
      ]);
      if (generation.current !== seq) return;
      setSummary(all);
      setListings(Object.fromEntries(dirs.filter((d) => d.result).map((d) => [d.path, d.result?.entries ?? []])));
      setError(dirs.some((d) => !d.result) ? "部分子目录已不存在，显示的是缓存前的内容" : "");
    } catch (err) {
      if (generation.current === seq) setError((err as Error).message);
    } finally {
      if (generation.current === seq) setLoading(false);
    }
  }, [task.id, expanded]);

  React.useEffect(() => {
    if (!active) return;
    void refresh();
    return () => {
      generation.current++;
    };
  }, [active, refresh]);

  // 运行中的任务每 5 秒轻量刷新（页面不可见时跳过）。
  React.useEffect(() => {
    if (!active || task.status !== "running" || task.paused) return;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, 5000);
    return () => clearInterval(timer);
  }, [active, task.status, task.paused, refresh]);

  const openPreview = React.useCallback(async (path: string) => {
    const seq = ++previewGeneration.current;
    setPreview({ path });
    if (isImage(path)) return; // 图片走 <img> 直接加载预览路由
    try {
      const file = await api.taskFileRead(task.id, path);
      if (previewGeneration.current === seq) setPreview({ path, file });
    } catch (err) {
      if (previewGeneration.current === seq) setPreview({ path, error: (err as Error).message });
    }
  }, [task.id]);

  // ?path= 深链：逐层展开祖先目录；指向文件时直接打开预览。
  React.useEffect(() => {
    if (!active || !requestedPath) return;
    let alive = true;
    const parts = requestedPath.split("/");
    const ancestors = parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join("/"));
    void api
      .taskFiles(task.id, requestedPath)
      .then(() => {
        if (alive) setExpanded((prev) => Array.from(new Set([...prev, ...ancestors, requestedPath])));
      })
      .catch(() => {
        if (!alive) return;
        setExpanded((prev) => Array.from(new Set([...prev, ...ancestors])));
        void openPreview(requestedPath);
      });
    return () => {
      alive = false;
    };
  }, [active, task.id, requestedPath, openPreview]);

  const locate = (path: string) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("tab", "files");
    if (path) params.set("path", path);
    else params.delete("path");
    router.replace(`/function/tasks/detail?${params}`, { scroll: false });
  };
  const workspacePath = (path: string) => `tasks/${task.id}${path ? `/${path}` : ""}`;
  const download = (path: string, archive = false) => {
    void api.taskFileDownload(task.id, path, archive).catch((err: unknown) => toast.error((err as Error).message));
  };
  const name = (entry: TaskFileEntry) => {
    if (entry.intent_id) return entry.intent_title || `意图 #${entry.intent_id}`;
    return KNOWN_DIRS[entry.path] ?? entry.name;
  };
  const rows: { entry: TaskFileEntry; depth: number }[] = [];
  const append = (path: string, depth: number) => {
    for (const entry of listings[path] ?? []) {
      rows.push({ entry, depth });
      if (entry.dir && expanded.includes(entry.path)) append(entry.path, depth + 1);
    }
  };
  if (mode === "tree") append("", 0);
  else for (const entry of summary?.entries ?? []) rows.push({ entry, depth: 0 });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant={mode === "tree" ? "secondary" : "ghost"} onClick={() => setMode("tree")}>
          目录树
        </Button>
        <Button variant={mode === "recent" ? "secondary" : "ghost"} onClick={() => setMode("recent")}>
          最近文件
        </Button>
        <span className="mr-auto text-muted-foreground text-sm">
          {summary && `共 ${summary.total} 个文件 · ${fileSize(summary.size)}`}
        </span>
        <Button variant="outline" disabled={loading} onClick={() => void refresh()}>
          <RefreshCwIcon />
          刷新
        </Button>
        <Button variant="outline" disabled={summary?.missing ?? true} onClick={() => download("", true)}>
          <DownloadIcon />
          导出全部
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      )}
      {mode === "recent" && summary?.truncated && (
        <p className="text-muted-foreground text-sm">文件过多，仅显示最近的 2000 个（计数与大小仍为全量）。</p>
      )}
      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>大小</TableHead>
              <TableHead>修改时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {!rows.length && (
              <TableRow>
                <TableCell colSpan={4} className="py-12 text-center text-muted-foreground">
                  {loading ? "加载中…" : summary?.missing ? "该任务还没有产生工作文件" : "目录为空"}
                </TableCell>
              </TableRow>
            )}
            {rows.map(({ entry, depth }) => (
              <TableRow key={entry.path}>
                <TableCell>
                  <div className="flex items-center gap-2" style={{ paddingLeft: depth * 20 }}>
                    <button
                      type="button"
                      className="flex min-w-0 items-center gap-2 text-left hover:underline"
                      disabled={entry.symlink}
                      aria-expanded={entry.dir ? expanded.includes(entry.path) : undefined}
                      onClick={() => {
                        if (entry.dir) {
                          if (expanded.includes(entry.path))
                            setExpanded((prev) =>
                              prev.filter((p) => p !== entry.path && !p.startsWith(`${entry.path}/`)),
                            );
                          else {
                            setExpanded((prev) => [...prev, entry.path]);
                            locate(entry.path);
                          }
                        } else {
                          locate(entry.path);
                        }
                      }}
                    >
                      {entry.dir ? (
                        <>
                          {expanded.includes(entry.path) ? (
                            <ChevronDownIcon className="size-4" />
                          ) : (
                            <ChevronRightIcon className="size-4" />
                          )}
                          <FolderIcon className="size-4 shrink-0" />
                        </>
                      ) : (
                        <FileIcon className="size-4 shrink-0" />
                      )}
                      <span className="max-w-lg truncate" title={entry.path}>
                        {mode === "recent" ? entry.path : name(entry)}
                      </span>
                    </button>
                    {entry.symlink && <span className="text-muted-foreground text-xs">链接（不可打开）</span>}
                    {entry.intent_state && <StatusBadge domain="intent" value={entry.intent_state} />}
                  </div>
                </TableCell>
                <TableCell className="whitespace-nowrap text-muted-foreground">
                  {entry.dir || entry.symlink ? "—" : fileSize(entry.size)}
                </TableCell>
                <TableCell className="whitespace-nowrap text-muted-foreground">
                  {new Date(entry.mtime).toLocaleString()}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={entry.symlink}
                      onClick={() => download(entry.path, entry.dir)}
                      title={entry.dir ? "导出 ZIP" : "下载"}
                      aria-label={entry.dir ? "导出 ZIP" : "下载"}
                    >
                      <DownloadIcon />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      title="复制工作空间路径"
                      aria-label="复制工作空间路径"
                      onClick={() => {
                        void navigator.clipboard
                          .writeText(workspacePath(entry.path))
                          .then(() => toast.success("已复制工作空间路径"))
                          .catch(() => toast.error("复制失败"));
                      }}
                    >
                      <CopyIcon />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <Dialog
        open={!!preview}
        onOpenChange={(open) => {
          if (!open) {
            previewGeneration.current++;
            setPreview(null);
            locate("");
          }
        }}
      >
        <DialogContent className="flex h-[80vh] flex-col sm:max-w-5xl">
          <DialogHeader>
            <DialogTitle className="truncate pr-6">{preview?.path}</DialogTitle>
          </DialogHeader>
          {preview && (
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => download(preview.path)}>
                下载
              </Button>
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-auto">
            {preview?.error && <p role="alert">{preview.error}</p>}
            {preview && !preview.error && isImage(preview.path) && (
              // biome-ignore lint/performance/noImgElement: authenticated raster preview
              <img
                src={api.taskFilePreview(task.id, preview.path) ?? undefined}
                alt={preview.path}
                className="mx-auto max-h-full object-contain"
                onError={() => setPreview((prev) => (prev ? { ...prev, error: "图片加载失败" } : prev))}
              />
            )}
            {preview && !preview.error && !isImage(preview.path) && !preview.file && <p>加载中…</p>}
            {preview?.file && !preview.error && (preview.file.binary || preview.file.too_large) && (
              <p>{preview.file.too_large ? "文件过大，请下载后查看。" : "二进制文件，不支持内联预览，请下载后查看。"}</p>
            )}
            {preview?.file && !preview.error && !preview.file.binary && !preview.file.too_large && (
              <pre className="rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">
                {preview.file.content ?? ""}
              </pre>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
