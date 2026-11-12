import type { TaskSchedule } from "./types";

// 日历式计划任务的展示文案与格式化（移植自 ARTEX 0.3.29 A7 的
// schedule-display.ts；本仓库无 i18n 体系，中文硬编码，去掉 TFunction 参数）。
// 服务端 schedule 消息本身就是中文，scheduleErrorText 在此裁剪为原样透传。
export function scheduleDisplay(locale = "zh-CN") {
  const weekdays = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];
  const formatTime = (value?: string) => (value ? new Date(value).toLocaleString(locale) : "—");
  const formatDateValue = (value?: string) => {
    if (!value) return "未设置";
    // Format date-only values without UTC conversion (which can change the day).
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
    if (!match) return value;
    return new Intl.DateTimeFormat(locale, { year: "numeric", month: "long", day: "numeric" }).format(
      new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3])),
    );
  };
  const formatClock = (value?: string) => (value ? value.slice(0, 5) : "未设置");
  const periodLabel = (item: TaskSchedule) => {
    if (item.schedule_type === "once") {
      return item.end_date
        ? `一次性 · ${formatDateValue(item.run_date)} 至 ${formatDateValue(item.end_date)}`
        : `一次性 · ${formatDateValue(item.run_date)}`;
    }
    const selected = item.weekdays.map((day) => weekdays[day - 1]).filter(Boolean);
    const days = selected.length ? new Intl.ListFormat(locale).format(selected) : "未选择星期";
    return `每周 · ${days}`;
  };
  const startLabel = (item: TaskSchedule) =>
    item.schedule_type === "once" ? `${formatDateValue(item.run_date)} ${formatClock(item.start_time)}` : formatClock(item.start_time);
  const endLabel = (item: TaskSchedule) => {
    if (item.schedule_type === "once" && item.end_date)
      return `${formatDateValue(item.end_date)} ${item.end_time ? formatClock(item.end_time) : "24:00"}`;
    if (!item.end_time) return "持续运行";
    const nextDay = formatClock(item.end_time) <= formatClock(item.start_time) ? "（次日）" : "";
    return `${formatClock(item.end_time)}${nextDay}`;
  };
  const windowLabel = (item: TaskSchedule) => {
    const start = startLabel(item);
    return item.end_time || (item.schedule_type === "once" && item.end_date)
      ? `${start} 至 ${endLabel(item)}`
      : `${start} 起持续运行`;
  };
  const timezoneLabel = (item: TaskSchedule) =>
    item.timezone_mode === "beijing" ? "中国北京时间" : item.timezone ? `系统时区（${item.timezone}）` : "系统当前时区";
  const nextWindowLabel = (value?: string, timezone?: string) => {
    if (!value) return "—";
    try {
      return new Intl.DateTimeFormat(locale, {
        timeZone: timezone && timezone !== "Local" ? timezone : undefined,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      }).format(new Date(value));
    } catch {
      return formatTime(value);
    }
  };
  const statusText = (item: TaskSchedule) =>
    (
      {
        waiting: "等待窗口",
        running: "窗口运行中",
        outside: "窗口外",
        completed: "已完成",
        error: "错误",
        paused: "已暂停",
      } as Record<TaskSchedule["status"], string>
    )[item.status] ?? "未知状态";
  const historyActionText = (action: string) =>
    (
      {
        running: "窗口开始",
        outside: "窗口结束",
        completed: "计划完成",
        waiting: "等待窗口",
        paused: "计划暂停",
        resume: "恢复任务",
        pause: "暂停任务",
        error: "执行错误",
      } as Record<string, string>
    )[action] ?? "状态变化";
  return {
    weekdays,
    formatTime,
    formatDateValue,
    formatClock,
    periodLabel,
    startLabel,
    endLabel,
    windowLabel,
    timezoneLabel,
    nextWindowLabel,
    statusText,
    historyActionText,
  };
}
