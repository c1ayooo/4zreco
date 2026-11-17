"use client";

import * as React from "react";

import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";

// useStoredColumnWidths 持久化表格列宽（px）。只存显式调整过的列——未调整的列
// 保持 table-fixed 的自动分配，列集或断点变化时无需迁移。加载时丢弃非法值。
export function useStoredColumnWidths<Column extends string>(key: string) {
  const [widths, setWidths] = React.useState<Partial<Record<Column, number>>>({});
  const [hydrated, setHydrated] = React.useState(false);

  React.useEffect(() => {
    const raw = getLocalStorageValue(key);
    if (raw) {
      try {
        const parsed = JSON.parse(raw) as unknown;
        if (parsed && typeof parsed === "object") {
          const next: Partial<Record<Column, number>> = {};
          for (const [column, value] of Object.entries(parsed)) {
            const width = Number(value);
            if (Number.isFinite(width) && width > 0) next[column as Column] = Math.round(width);
          }
          setWidths(next);
        }
      } catch {
        // Ignore malformed or legacy preferences and retain auto widths.
      }
    }
    setHydrated(true);
  }, [key]);

  React.useEffect(() => {
    if (!hydrated) return;
    setLocalStorageValue(key, JSON.stringify(widths));
  }, [hydrated, key, widths]);

  const setColumnWidth = React.useCallback((column: Column, width: number) => {
    setWidths((current) => (current[column] === width ? current : { ...current, [column]: width }));
  }, []);

  const resetColumnWidth = React.useCallback((column: Column) => {
    setWidths((current) => {
      if (current[column] === undefined) return current;
      const next = { ...current };
      delete next[column];
      return next;
    });
  }, []);

  return [widths, setColumnWidth, resetColumnWidth] as const;
}
