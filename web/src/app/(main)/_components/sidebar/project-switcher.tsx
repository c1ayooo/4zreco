"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { CheckIcon, ChevronsUpDownIcon, FolderKanbanIcon, PlusIcon, Settings2Icon } from "lucide-react";
import { toast } from "sonner";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { useProjectStore } from "@/stores/project/project-provider";

// 侧栏全局项目切换器：切到哪个项目，对话页新会话默认挂载、任务列表按项目过滤。
// projectId=0 = 全部（未筛选），保持存量未挂项目的任务/对话可见。
export function ProjectSwitcher() {
  const router = useRouter();
  const projects = useProjectStore((s) => s.projects);
  const projectId = useProjectStore((s) => s.projectId);
  const status = useProjectStore((s) => s.status);
  const setProject = useProjectStore((s) => s.setProject);

  const current = projects.find((p) => p.id === projectId) ?? null;

  function switchTo(id: number) {
    if (id === projectId) return;
    const target = projects.find((p) => p.id === id);
    setProject(id);
    toast.success(id === 0 ? "已切到全部项目" : `已切到项目「${target?.name ?? id}」`);
    // 切换后落到任务页：过滤视图立即反映新上下文（4zrec 同款）。
    router.push("/function/tasks");
  }

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent" disabled={status !== "ready"}>
              <span className="bg-primary/10 text-primary flex size-8 shrink-0 items-center justify-center rounded-lg">
                <FolderKanbanIcon className="size-4" />
              </span>
              <span className="grid min-w-0 flex-1 text-left leading-tight">
                <span className="text-muted-foreground text-[11px]">当前项目</span>
                <span className="truncate font-medium">
                  {status !== "ready" ? "加载中…" : (current?.name ?? "全部项目")}
                </span>
              </span>
              <ChevronsUpDownIcon className="text-muted-foreground ml-auto size-4 shrink-0" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-64" align="start" side="right">
            <DropdownMenuLabel className="text-muted-foreground text-xs">切换项目</DropdownMenuLabel>
            <div className="max-h-64 overflow-y-auto">
              <DropdownMenuItem onClick={() => switchTo(0)} className="gap-2">
                <span className="min-w-0 flex-1">全部项目</span>
                {projectId === 0 ? <CheckIcon className="text-primary size-4 shrink-0" /> : null}
              </DropdownMenuItem>
              {projects.map((p) => (
                <DropdownMenuItem key={p.id} onClick={() => switchTo(p.id)} className="gap-2">
                  <span className="min-w-0 flex-1 truncate">
                    {p.name}
                    {p.status === "archived" ? <span className="text-muted-foreground ml-1 text-[11px]">已归档</span> : null}
                  </span>
                  <span className="text-muted-foreground shrink-0 text-[11px] tabular-nums">{p.task_count} 任务</span>
                  {p.id === projectId ? <CheckIcon className="text-primary size-4 shrink-0" /> : null}
                </DropdownMenuItem>
              ))}
              {projects.length === 0 && (
                <div className="text-muted-foreground px-2 py-3 text-center text-xs">还没有项目，先新建一个</div>
              )}
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => router.push("/function/projects")} className="cursor-pointer">
              <Settings2Icon className="size-4" /> 管理项目
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link prefetch={false} href="/function/projects?create=1" className="cursor-pointer">
                <PlusIcon className="size-4" /> 新建项目
              </Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
