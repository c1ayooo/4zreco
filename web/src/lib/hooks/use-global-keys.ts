"use client";

import { useEffect } from "react";

import { useRouter } from "next/navigation";

// SearchDialog 的「打开」能力经 window 自定义事件暴露：本 hook 派发，SearchDialog
// 自行监听。侵入最小——不需要把弹层状态提升到布局层；SearchDialog 未挂载时
// （任务详情全幅页）事件落空为无操作。
export const OPEN_SEARCH_EVENT = "4zreco:open-search";

function openSearchDialog() {
  window.dispatchEvent(new CustomEvent(OPEN_SEARCH_EVENT));
}

// 输入焦点守卫：光标在可输入元素（input/textarea/select/contenteditable，
// 含 Radix 组合框/文本框角色，避免与下拉框 typeahead 双触发）上时不消费任何键。
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  if (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  ) {
    return true;
  }
  const role = target.getAttribute("role");
  return role === "combobox" || role === "textbox";
}

// Radix 弹层守卫：任意 Dialog/AlertDialog/Sheet（role=dialog|alertdialog）或
// popper 定位弹层（Select/Popover/DropdownMenu/Tooltip）打开时不消费任何键。
export function isOverlayOpen(): boolean {
  if (typeof document === "undefined") return false;
  return Boolean(document.querySelector('[role="dialog"], [role="alertdialog"], [data-radix-popper-content-wrapper]'));
}

// g 前缀序列窗口：800ms 内的第二键才生效。
const G_SEQUENCE_WINDOW_MS = 800;

// 全局键：`/` 打开搜索；`g t` → 任务列表，`g d` → 仪表盘。
// keydown 捕获监听；守卫（输入焦点/Radix 弹层/组合键/输入法）不过则直接放行，
// 不吞事件。单条按键的处理返回是否消费（消费 = preventDefault 且动作已执行）。
export function useGlobalKeys() {
  const router = useRouter();

  useEffect(() => {
    let gArmedAt = 0;
    let gTimer = 0;

    const disarmG = () => {
      gArmedAt = 0;
      if (gTimer) {
        window.clearTimeout(gTimer);
        gTimer = 0;
      }
    };

    const consume = (e: KeyboardEvent): boolean => {
      if (e.isComposing || e.metaKey || e.ctrlKey || e.altKey) return false;
      if (isTypingTarget(e.target) || isOverlayOpen()) return false;

      if (gArmedAt && Date.now() - gArmedAt <= G_SEQUENCE_WINDOW_MS) {
        disarmG();
        if (e.key === "t") {
          e.preventDefault();
          router.push("/function/tasks");
          return true;
        }
        if (e.key === "d") {
          e.preventDefault();
          router.push("/dashboard");
          return true;
        }
        // 序列不匹配则落到下面的单键分支（如 `g /` 仍打开搜索）。
      }

      if (e.key === "/") {
        if (e.repeat) return false;
        e.preventDefault();
        openSearchDialog();
        return true;
      }

      if (e.key === "g") {
        disarmG();
        if (!e.repeat) {
          gArmedAt = Date.now();
          gTimer = window.setTimeout(disarmG, G_SEQUENCE_WINDOW_MS);
        }
        // 前缀键不消费：无后续序列时 `g` 不吞任何默认行为。
        return false;
      }

      return false;
    };

    const onKeydown = (e: KeyboardEvent) => {
      consume(e);
    };

    document.addEventListener("keydown", onKeydown, true);
    return () => {
      document.removeEventListener("keydown", onKeydown, true);
      disarmG();
    };
  }, [router]);
}
