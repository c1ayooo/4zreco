"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, FileDownIcon, FileTextIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { copyText } from "@/lib/utils";

export function ReportTab({ taskId }: { taskId: string }) {
  const [report, setReport] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [copied, setCopied] = React.useState(false);
  const [attempt, setAttempt] = React.useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt invalidates the report fetch without changing taskId.
  React.useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    api
      .report(taskId)
      .then((text) => {
        if (active) setReport(text);
      })
      .catch((e) => {
        if (!active) return;
        setReport("");
        setError((e as Error).message || "加载失败");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [taskId, attempt]);

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success("已复制 Markdown");
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("复制失败，请手动选择文本复制");
    }
  }

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col gap-3 bg-muted/20 p-4">
        {["w-11/12", "w-full", "w-5/6", "w-10/12", "w-2/3"].map((w) => (
          <Skeleton key={w} className={`h-4 ${w}`} />
        ))}
      </div>
    );
  } else if (error) {
    content = (
      <Alert variant="destructive">
        <AlertDescription>
          <div className="flex flex-wrap items-center gap-2">
            <span>报告加载失败：{error}</span>
            <Button variant="outline" size="sm" onClick={() => setAttempt((v) => v + 1)}>
              重试
            </Button>
          </div>
        </AlertDescription>
      </Alert>
    );
  } else if (report) {
    content = (
      <div className="max-h-[60vh] overflow-auto bg-muted/20 p-4">
        <Markdown text={report} />
      </div>
    );
  } else {
    content = (
      <Empty className="py-16">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FileTextIcon />
          </EmptyMedia>
          <EmptyTitle>暂无报告</EmptyTitle>
          <EmptyDescription>任务产生可归档结果后，报告会生成在这里。</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FileTextIcon className="size-4" /> 渗透测试报告（Markdown）
        </CardTitle>
        <div className="flex gap-2">
          {report && (
            <Button size="sm" variant="outline" onClick={copy}>
              {copied ? <CheckIcon /> : <CopyIcon />} 复制
            </Button>
          )}
          {report && (
            <Button size="sm" variant="outline" onClick={() => api.downloadTaskDocx(taskId)}>
              <FileDownIcon /> 导出 Word
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  );
}
