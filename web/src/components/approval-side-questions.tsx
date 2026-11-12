"use client";

import * as React from "react";

import { ArrowUpIcon, SquareIcon } from "lucide-react";

import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from "@/components/ui/input-group";
import { useSideQuestions } from "@/hooks/use-side-questions";

const statusLabels: Record<string, string> = {
  running: "回答中",
  completed: "已完成",
  failed: "失败",
  cancelled: "已停止",
  interrupted: "已中断",
};

// B2 审批旁路预置快捷提问：聚焦审查时的三类核心关切（行为解释 / 触发依据 / 风险）。
const quickQuestions = ["这个命令/脚本的作用是什么？", "为什么会触发这次审批？", "允许执行会有什么风险？"];

// 审批详情内嵌的旁路提问区（ARTEX 移植 B2）。复用 use-side-questions hook，
// parent = /api/intercept/history/{id}；快照由后端从冻结的审查 audit 现建，
// 只读解释材料，不写主会话、不改审批状态。仅在详情含 audit 时挂载。
export function ApprovalSideQuestions({ approvalID }: { approvalID: number }) {
  const side = useSideQuestions(`/api/intercept/history/${approvalID}`);
  const { setOpen } = side;
  // 面板常驻：挂载即标记 open，激活 hook 的轮询与 SSE 通道。
  React.useEffect(() => {
    setOpen(true);
  }, [setOpen]);

  return (
    <section aria-label="审批旁路提问" className="flex min-w-0 flex-col gap-3 border-t pt-4">
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-medium text-muted-foreground text-xs">旁路提问</h3>
        {side.snapshot ? (
          <p className="truncate text-muted-foreground text-xs">
            {side.snapshot.model.model} · 上下文更新于 {new Date(side.snapshot.captured_at).toLocaleString()}
          </p>
        ) : null}
      </div>
      {side.items.length === 0 && !side.loading ? (
        <div className="flex flex-wrap gap-2">
          {quickQuestions.map((question) => (
            <Button
              key={question}
              variant="outline"
              size="sm"
              disabled={side.busy || !!side.running}
              onClick={() => void side.ask(question)}
            >
              {question}
            </Button>
          ))}
        </div>
      ) : null}
      {side.loading ? null : (
        <div className="flex min-w-0 flex-col gap-4">
          {side.items.map((item) => (
            <article key={item.id} className="flex min-w-0 flex-col gap-2">
              <div className="whitespace-pre-wrap break-words rounded-lg bg-muted p-3 text-sm">{item.question}</div>
              <div className="flex flex-wrap items-center gap-2 text-muted-foreground text-xs">
                <Badge variant="secondary">{statusLabels[item.status]}</Badge>
                <time dateTime={item.snapshot_at} title={new Date(item.snapshot_at).toLocaleString()}>
                  上下文 {new Date(item.snapshot_at).toLocaleTimeString()}
                </time>
              </div>
              {item.answer && <Markdown text={item.answer} />}
              {!item.answer && item.status === "running" && (
                <p role="status" className="text-muted-foreground text-sm">
                  正在回答…
                </p>
              )}
              {item.error && (
                <Alert variant="destructive">
                  <AlertDescription>{item.error}</AlertDescription>
                </Alert>
              )}
            </article>
          ))}
        </div>
      )}
      {side.error || side.snapshot?.reason ? (
        <Alert variant="destructive">
          <AlertDescription>{side.error || side.snapshot?.reason}</AlertDescription>
        </Alert>
      ) : null}
      <InputGroup className="min-h-9">
        <InputGroupTextarea
          rows={1}
          className="max-h-36 min-h-9 overflow-y-auto"
          aria-label="旁路问题"
          placeholder="询问当前审批记录…"
          value={side.draft}
          maxLength={4000}
          disabled={side.busy}
          onChange={(event) => side.setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
              event.preventDefault();
              void side.ask(side.draft);
            }
          }}
        />
        <InputGroupAddon align="block-end">
          <span className="text-muted-foreground text-xs">独立问答 · 无工具执行 · 不影响审批状态</span>
          {side.running ? (
            <InputGroupButton
              className="ml-auto"
              variant="destructive"
              size="icon-xs"
              onClick={() => void side.stop()}
              aria-label="停止旁路回答"
            >
              <SquareIcon />
            </InputGroupButton>
          ) : (
            <InputGroupButton
              className="ml-auto"
              variant="default"
              size="icon-xs"
              onClick={() => void side.ask(side.draft)}
              disabled={side.busy || !side.draft.trim() || !side.snapshot?.available}
              aria-label="发送旁路问题"
            >
              <ArrowUpIcon />
            </InputGroupButton>
          )}
        </InputGroupAddon>
      </InputGroup>
    </section>
  );
}
