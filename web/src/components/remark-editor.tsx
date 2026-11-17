"use client";

import * as React from "react";

import { PencilIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { MAX_TASK_REMARK_RUNES } from "@/lib/types";

type EditorProps = {
  value?: string;
  label: string;
  onSave: (value: string) => Promise<void>;
};

// 任务/模板备注的行内编辑器（ARTEX 移植 A1）：点击文本或铅笔进入编辑，Enter 保存、
// Esc 取消、失焦按上下文保存或取消。文案中文硬编码（本仓库无 i18n 体系）。
export function RemarkEditor(props: EditorProps) {
  return <InlineTextEditor {...props} maxCharacters={MAX_TASK_REMARK_RUNES} />;
}

function InlineTextEditor({ value = "", label, onSave, maxCharacters }: EditorProps & { maxCharacters: number }) {
  const [editing, setEditing] = React.useState(false);
  const [draft, setDraft] = React.useState(value);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<{ kind: "length" | "save"; message: string } | null>(null);
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const cancelOnBlurRef = React.useRef(false);
  const savingRef = React.useRef(false);
  const errorID = React.useId();

  React.useEffect(() => {
    if (!editing) setDraft(value);
  }, [editing, value]);

  function refocus() {
    requestAnimationFrame(() => textareaRef.current?.focus());
  }

  async function finishEditing() {
    if (savingRef.current) return;
    if (cancelOnBlurRef.current) {
      cancelOnBlurRef.current = false;
      setDraft(value);
      setError(null);
      setEditing(false);
      return;
    }
    const next = draft.trim();
    if (next === value.trim()) {
      setEditing(false);
      return;
    }
    if (Array.from(next).length > maxCharacters) {
      setError({ kind: "length", message: `备注最多 ${maxCharacters} 个字符` });
      refocus();
      return;
    }
    savingRef.current = true;
    setSaving(true);
    try {
      await onSave(next);
      toast.success("备注已保存");
      setEditing(false);
    } catch (cause) {
      setError({ kind: "save", message: (cause as Error)?.message || "未知错误" });
      refocus();
    } finally {
      savingRef.current = false;
      setSaving(false);
    }
  }

  if (editing) {
    return (
      <div className="flex min-w-0 flex-col gap-1 font-medium">
        <Textarea
          value={draft}
          rows={1}
          autoFocus
          disabled={saving}
          aria-busy={saving}
          aria-label={`编辑${label}的备注`}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? errorID : undefined}
          className="max-h-40 min-h-7 w-full min-w-0 resize-none px-2 py-1 [overflow-wrap:anywhere]"
          title="Shift+Enter 换行，Enter 保存，Esc 取消"
          onFocus={(event) => event.currentTarget.select()}
          onChange={(event) => {
            setDraft(event.target.value);
            setError(null);
          }}
          onBlur={() => void finishEditing()}
          onKeyDown={(event) => {
            if (event.nativeEvent.isComposing) return;
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              event.currentTarget.blur();
            } else if (event.key === "Escape") {
              event.preventDefault();
              cancelOnBlurRef.current = true;
              event.currentTarget.blur();
            }
          }}
        />
        {saving && <Spinner className="shrink-0" />}
        {error ? (
          <p id={errorID} role="alert" className="whitespace-normal text-destructive text-xs">
            {error.message}
          </p>
        ) : null}
      </div>
    );
  }

  const startEditing = () => {
    setDraft(value);
    setError(null);
    setEditing(true);
  };
  return (
    // max-w-full：表格固定列宽场景下容器跟随列宽截断（展示态文本已 truncate），
    // 固定 max-w 会在列被拖窄后溢出叠到相邻列。
    <div className="group/inline-editor flex w-fit max-w-full min-w-0 items-center gap-1 font-medium">
      <button
        type="button"
        className="min-w-0 truncate rounded-sm text-left hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label={`点击编辑${label}的备注`}
        title={value.length > 0 ? value : "点击添加备注"}
        onClick={startEditing}
      >
        {value.length > 0 ? (
          <span className="block max-w-full truncate">{value}</span>
        ) : (
          <span className="text-muted-foreground">添加备注</span>
        )}
      </button>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            className="shrink-0 opacity-100 transition-opacity [@media(hover:hover)]:opacity-0 [@media(hover:hover)]:group-focus-within:opacity-100 [@media(hover:hover)]:group-hover:opacity-100 [@media(hover:hover)]:group-focus-within/inline-editor:opacity-100 [@media(hover:hover)]:group-hover/inline-editor:opacity-100"
            aria-label={`编辑${label}的备注`}
            onClick={startEditing}
          >
            <PencilIcon />
          </Button>
        </TooltipTrigger>
        <TooltipContent side="top" sideOffset={6}>
          编辑备注
        </TooltipContent>
      </Tooltip>
    </div>
  );
}
