import { createStore } from "zustand/vanilla";

import { api } from "@/lib/api";
import type { Project } from "@/lib/types";

export const PROJECT_ID_STORAGE_KEY = "4zreco_project_id";

export type ProjectStatus = "idle" | "loading" | "ready";

// 全局项目上下文：侧边栏切换器写入，对话页/任务页读取。
// 与 4zrec 的差异：不强制单项目口径——projectId=0 表示「全部（未筛选）」，
// 也是默认值；存量部署的任务/对话都没挂项目，强制选中会让它们全部消失。
export type ProjectState = {
  projects: Project[];
  projectId: number;
  status: ProjectStatus;
  booted: boolean;
  /** 首次挂载拉项目列表并恢复上次选中（无效则回落 0=全部）。 */
  boot: () => Promise<void>;
  /** 切换当前项目并持久化。0 = 全部。 */
  setProject: (id: number) => void;
  /** 重拉项目列表；当前项目被删时回落 0。返回最新列表。 */
  reloadProjects: () => Promise<Project[]>;
};

function readSavedProjectId(): number {
  try {
    return Number(window.localStorage.getItem(PROJECT_ID_STORAGE_KEY) || "0") || 0;
  } catch {
    return 0;
  }
}

function persistProjectId(id: number) {
  try {
    window.localStorage.setItem(PROJECT_ID_STORAGE_KEY, String(id));
  } catch {
    /* 隐私模式等场景写不进就只留在内存 */
  }
}

export const createProjectStore = () =>
  createStore<ProjectState>()((set, get) => ({
    projects: [],
    projectId: 0,
    status: "idle",
    booted: false,
    boot: async () => {
      if (get().booted) return;
      set({ booted: true, status: "loading" });
      try {
        const list = await api.projects();
        const saved = readSavedProjectId();
        const next = list.some((p) => p.id === saved) ? saved : 0;
        set({ projects: list, projectId: next, status: "ready" });
      } catch {
        // 拉取失败保持空态，reloadProjects 可重试。
        set({ status: "ready" });
      }
    },
    setProject: (id) => {
      set({ projectId: id });
      persistProjectId(id);
    },
    reloadProjects: async () => {
      try {
        const list = await api.projects();
        const prev = get().projectId;
        const next = list.some((p) => p.id === prev) ? prev : 0;
        set({ projects: list, projectId: next });
        if (next !== prev) persistProjectId(next);
        return list;
      } catch {
        return get().projects;
      }
    },
  }));
