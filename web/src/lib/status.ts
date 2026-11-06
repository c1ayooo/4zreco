// Centralised status → color/label semantics, reused across the whole app.
// Spec §8.3: 意图 / 覆盖 / 任务 / 严重度 each have a consistent color set.
// Tone 名是对外 API（消费者按名取类串），保持不变；色面一律走语义令牌：
// blue→info、green→success、amber→warning、red/rose→destructive、violet→primary、
// slate→muted 系，底章沿用 bg-*/15 text-* 惯例。

export type Tone = "neutral" | "blue" | "green" | "amber" | "red" | "rose" | "violet" | "slate";

export const toneClasses: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-transparent",
  blue: "bg-info/15 text-info border-info/20",
  green: "bg-success/15 text-success border-success/20",
  amber: "bg-warning/15 text-warning border-warning/20",
  red: "bg-destructive/15 text-destructive border-destructive/20",
  // rose 用作「严重」——实心高强调,视觉上明显高于「高危」的软红描边。
  rose: "bg-destructive text-white border-destructive",
  violet: "bg-primary/15 text-primary border-primary/20",
  slate: "bg-muted-foreground/15 text-muted-foreground border-transparent",
};

export const toneDot: Record<Tone, string> = {
  neutral: "bg-muted-foreground",
  blue: "bg-info",
  green: "bg-success",
  amber: "bg-warning",
  red: "bg-destructive",
  rose: "bg-white",
  violet: "bg-primary",
  slate: "bg-muted-foreground",
};

interface StatusMeta {
  label: string;
  tone: Tone;
}

const intent: Record<string, StatusMeta> = {
  open: { label: "待领", tone: "slate" },
  running: { label: "执行中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  done: { label: "已完成", tone: "green" },
  // blocked = 模型/API/网络故障重试用尽，这条意图基本没真正探成（非目标拦截）。
  blocked: { label: "执行出错", tone: "red" },
  // exhausted = 达到步数/时间预算被中途掐断、只写回部分结果（非方向已探尽）。
  exhausted: { label: "预算耗尽", tone: "violet" },
  // stopped = 历史软删除状态（保留,历史数据）。
  stopped: { label: "已停止", tone: "slate" },
  // deleted = 用户假删除了该意图（保留节点与血缘，删除原因见 delete_reason 字段）。
  deleted: { label: "已删除", tone: "slate" },
};

const task: Record<string, StatusMeta> = {
  created: { label: "已创建", tone: "slate" },
  queued: { label: "排队中", tone: "amber" },
  running: { label: "运行中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  done: { label: "已完成", tone: "green" },
  failed: { label: "失败", tone: "red" },
  timeout: { label: "已超时", tone: "amber" },
};

const severity: Record<string, StatusMeta> = {
  critical: { label: "严重", tone: "rose" },
  high: { label: "高危", tone: "red" },
  medium: { label: "中危", tone: "amber" },
  low: { label: "低危", tone: "slate" },
};

const finding: Record<string, StatusMeta> = {
  pending: { label: "待处理", tone: "amber" },
  in_progress: { label: "处理中", tone: "blue" },
  confirmed: { label: "已确认", tone: "red" },
  resolved: { label: "已处理", tone: "green" },
  fixed: { label: "已修复", tone: "green" },
  false_positive: { label: "误报", tone: "slate" },
  ignored: { label: "忽略", tone: "neutral" },
  duplicate: { label: "重复", tone: "neutral" },
  risk_accepted: { label: "风险接受", tone: "violet" },
};

const engine: Record<string, StatusMeta> = {
  exploring: { label: "探索中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  stalled: { label: "停滞", tone: "red" },
  idle: { label: "空闲", tone: "neutral" },
};

const goal: Record<string, StatusMeta> = {
  open: { label: "进行中", tone: "blue" },
  met: { label: "已达成", tone: "green" },
  abandoned: { label: "已放弃", tone: "slate" },
};

const audit: Record<string, StatusMeta> = {
  allow: { label: "放行", tone: "green" },
  block: { label: "拦截", tone: "red" },
};

const node: Record<string, StatusMeta> = {
  observed: { label: "观测", tone: "slate" },
  confirmed: { label: "确认", tone: "green" },
  tombstoned: { label: "废弃", tone: "neutral" },
};

// 推送投递状态。sending 用 blue 而不是 amber：它不是「有问题」，
// 而是「已被领取、正在发」，与 pending 的等待语义要能区分开。
const delivery: Record<string, StatusMeta> = {
  pending: { label: "待发送", tone: "amber" },
  sending: { label: "发送中", tone: "blue" },
  sent: { label: "已送达", tone: "green" },
  failed: { label: "失败", tone: "red" },
  skipped: { label: "已跳过", tone: "neutral" },
};

const maps = {
  intent,
  task,
  severity,
  finding,
  engine,
  goal,
  audit,
  node,
  delivery,
} as const;

export type StatusDomain = keyof typeof maps;

export function statusMeta(domain: StatusDomain, key: string): StatusMeta {
  return maps[domain][key] ?? { label: key, tone: "neutral" };
}
