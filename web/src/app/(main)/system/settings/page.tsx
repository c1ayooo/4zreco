"use client";

import * as React from "react";

import {
  CpuIcon,
  FlaskConicalIcon,
  GaugeIcon,
  KeyboardIcon,
  MessageSquareIcon,
  RadioTowerIcon,
  SearchIcon,
  ShieldAlertIcon,
  TimerResetIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { CHAT_SEND_MODE_OPTIONS, type ChatSendMode, setChatSendMode, useChatSendMode } from "@/lib/chat-send-mode";
import type { ImBotSettingsInput, Settings } from "@/lib/types";
import { cn } from "@/lib/utils";

import { UpdateCard } from "./_components/update-card";

export default function SystemSettingsPage() {
  const [trafficCapture, setTrafficCapture] = React.useState(false);
  const [trafficProxyAlive, setTrafficProxyAlive] = React.useState(true);
  const [agentTrafficBinding, setAgentTrafficBinding] = React.useState(false);
  const [webSearch, setWebSearch] = React.useState(false);
  const [backend, setBackend] = React.useState("ddgs");
  const [braveKeySet, setBraveKeySet] = React.useState(false);
  const [braveKeyInput, setBraveKeyInput] = React.useState("");
  const [tavilyKeySet, setTavilyKeySet] = React.useState(false);
  const [tavilyKeyInput, setTavilyKeyInput] = React.useState("");
  const [savingTavilyKey, setSavingTavilyKey] = React.useState(false);
  const [proxyInput, setProxyInput] = React.useState("");
  const [savingProxy, setSavingProxy] = React.useState(false);
  const [globalProxyInput, setGlobalProxyInput] = React.useState("");
  const [savingGlobalProxy, setSavingGlobalProxy] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [savingKey, setSavingKey] = React.useState(false);
  const [pyInterp, setPyInterp] = React.useState("");
  const [workers, setWorkers] = React.useState("3");
  const [savingWorkers, setSavingWorkers] = React.useState(false);
  // 数值校验错误就近显示（toast 只留给请求失败）。
  const [workersError, setWorkersError] = React.useState("");
  const [autoFinishError, setAutoFinishError] = React.useState("");
  const [intentBudgetError, setIntentBudgetError] = React.useState("");
  const [compactionError, setCompactionError] = React.useState("");
  // 任务自动收尾（v0.5.0）。
  const [autoFinishEnabled, setAutoFinishEnabled] = React.useState(true);
  const [autoFinishIdle, setAutoFinishIdle] = React.useState("3");
  const [autoFinishMin, setAutoFinishMin] = React.useState("5");
  const [autoFinishCoverage, setAutoFinishCoverage] = React.useState("0");
  const [autoFinishMax, setAutoFinishMax] = React.useState("80");
  const [intentBudgetEnabled, setIntentBudgetEnabled] = React.useState(true);
  const [intentBudgetTokens, setIntentBudgetTokens] = React.useState("3000000");
  const [savingIntentBudget, setSavingIntentBudget] = React.useState(false);
  const [savingAutoFinish, setSavingAutoFinish] = React.useState(false);
  // 冷节点压缩的输出预算与墙钟上限。0=用默认值(65536 token / 20 分钟)。
  const [compactionTokens, setCompactionTokens] = React.useState("0");
  const [compactionTimeout, setCompactionTimeout] = React.useState("0");
  const [compactionMembers, setCompactionMembers] = React.useState("0");
  const [savingCompaction, setSavingCompaction] = React.useState(false);
  // B10:压缩器钉住的 LLM 配置。"0"=跟随规划器(历史行为)。选项来自 LLM 配置列表,
  // 加载失败时不挡页面,只显示「跟随规划器」一项。
  const [compactorProfile, setCompactorProfile] = React.useState("0");
  const [llmProfileOpts, setLlmProfileOpts] = React.useState<{ id: string; name: string }[]>([]);
  // 操作约束注入范围(默认都开)。
  const [injectPlanner, setInjectPlanner] = React.useState(true);
  const [injectWorker, setInjectWorker] = React.useState(true);
  // 实验功能:noa 上下文压缩(默认关)。
  const [noaCompaction, setNoaCompaction] = React.useState(false);
  // IM 交互机器人：四平台凭据（密钥 *_set 只读回显，输入框留空=不改）。
  const [imAgent, setImAgent] = React.useState("auto");
  const [imFeishuOn, setImFeishuOn] = React.useState(false);
  const [imFeishuAppID, setImFeishuAppID] = React.useState("");
  const [imFeishuSecret, setImFeishuSecret] = React.useState("");
  const [imFeishuSecretSet, setImFeishuSecretSet] = React.useState(false);
  const [imDingtalkOn, setImDingtalkOn] = React.useState(false);
  const [imDingtalkID, setImDingtalkID] = React.useState("");
  const [imDingtalkSecret, setImDingtalkSecret] = React.useState("");
  const [imDingtalkSecretSet, setImDingtalkSecretSet] = React.useState(false);
  const [imTelegramOn, setImTelegramOn] = React.useState(false);
  const [imTelegramToken, setImTelegramToken] = React.useState("");
  const [imTelegramTokenSet, setImTelegramTokenSet] = React.useState(false);
  const [imTelegramProxy, setImTelegramProxy] = React.useState("");
  const [imWecomOn, setImWecomOn] = React.useState(false);
  const [imWecomCorpID, setImWecomCorpID] = React.useState("");
  const [imWecomSecret, setImWecomSecret] = React.useState("");
  const [imWecomSecretSet, setImWecomSecretSet] = React.useState(false);
  const [imWecomAgentID, setImWecomAgentID] = React.useState("");
  const [imWecomCallbackToken, setImWecomCallbackToken] = React.useState("");
  const [imWecomCallbackTokenSet, setImWecomCallbackTokenSet] = React.useState(false);
  const [imWecomAESKey, setImWecomAESKey] = React.useState("");
  const [imWecomAESKeySet, setImWecomAESKeySet] = React.useState(false);
  const [imWecomCallbackURL, setImWecomCallbackURL] = React.useState("");
  const [imWecomBaseURLSet, setImWecomBaseURLSet] = React.useState(false);
  const [savingIM, setSavingIM] = React.useState("");
  // 纯前端偏好：不走 /api/settings，直接读写 localStorage。
  const sendMode = useChatSendMode();

  const apply = React.useCallback((s: Settings) => {
    setTrafficCapture(!!s.traffic_capture);
    // 字段缺失（旧后端）视为存活，不误报。
    setTrafficProxyAlive(s.traffic_proxy_alive !== false);
    setAgentTrafficBinding(!!s.agent_traffic_binding);
    setWebSearch(!!s.web_search_enabled);
    setBackend(s.web_search_backend || "ddgs");
    setBraveKeySet(!!s.brave_key_set);
    setTavilyKeySet(!!s.tavily_key_set);
    setProxyInput(s.web_search_proxy ?? "");
    setGlobalProxyInput(s.global_proxy ?? "");
    setPyInterp(s.python_interpreter ?? "");
    setWorkers(String(s.workers ?? 3));
    setCompactionTokens(String(s.compaction_max_tokens ?? 0));
    setCompactionTimeout(String(s.compaction_timeout_seconds ?? 0));
    setCompactionMembers(String(s.compaction_max_members ?? 0));
    setCompactorProfile(String(s.compactor_profile_id ?? 0));
    setInjectPlanner(s.constraints_inject_planner !== false);
    setInjectWorker(s.constraints_inject_worker !== false);
    setNoaCompaction(!!s.noa_compaction);
    setAutoFinishEnabled(s.auto_finish_enabled !== false);
    setAutoFinishIdle(String(s.auto_finish_idle_rounds ?? 3));
    setAutoFinishMin(String(s.auto_finish_min_rounds ?? 5));
    setAutoFinishCoverage(String(s.auto_finish_coverage_pct ?? 0));
    setAutoFinishMax(String(s.auto_finish_max_rounds ?? 80));
    setIntentBudgetEnabled(s.intent_budget_enabled !== false);
    setIntentBudgetTokens(String(s.intent_budget_tokens ?? 3000000));
    const im = s.im_bot;
    if (im) {
      setImAgent(im.agent_key || "auto");
      setImFeishuOn(im.feishu.enabled);
      setImFeishuAppID(im.feishu.app_id);
      setImFeishuSecretSet(im.feishu.app_secret_set);
      setImDingtalkOn(im.dingtalk.enabled);
      setImDingtalkID(im.dingtalk.client_id);
      setImDingtalkSecretSet(im.dingtalk.client_secret_set);
      setImTelegramOn(im.telegram.enabled);
      setImTelegramTokenSet(im.telegram.bot_token_set);
      setImTelegramProxy(im.telegram.proxy);
      setImWecomOn(im.wecom.enabled);
      setImWecomCorpID(im.wecom.corp_id);
      setImWecomSecretSet(im.wecom.corp_secret_set);
      setImWecomAgentID(im.wecom.agent_id ? String(im.wecom.agent_id) : "");
      setImWecomCallbackTokenSet(im.wecom.callback_token_set);
      setImWecomAESKeySet(im.wecom.encoding_aes_key_set);
      setImWecomCallbackURL(im.wecom.callback_url);
      setImWecomBaseURLSet(im.wecom.base_url_set);
    }
  }, []);

  const saveWorkers = () => {
    const n = Number(workers);
    if (!Number.isInteger(n) || n <= 0) {
      setWorkersError("并发数必须是大于 0 的整数");
      return;
    }
    setWorkersError("");
    setSavingWorkers(true);
    api
      .setSettings({ workers: n })
      .then((s) => {
        apply(s);
        toast.success("已保存并发工作 agent 数（对之后启动的任务生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingWorkers(false));
  };

  const saveAutoFinish = () => {
    const idle = Number(autoFinishIdle);
    const min = Number(autoFinishMin);
    const cov = Number(autoFinishCoverage);
    const max = Number(autoFinishMax);
    if (!Number.isInteger(idle) || idle < 2 || idle > 20) {
      setAutoFinishError("连续无新增轮数必须在 2–20 之间");
      return;
    }
    if (!Number.isInteger(min) || min < 1 || min > 50) {
      setAutoFinishError("最少规划轮数必须在 1–50 之间");
      return;
    }
    if (!Number.isInteger(cov) || cov < 0 || cov > 100) {
      setAutoFinishError("覆盖率阈值必须在 0–100 之间（0 = 关闭）");
      return;
    }
    if (!Number.isInteger(max) || max < 0 || max > 500) {
      setAutoFinishError("最大规划轮数必须在 0–500 之间（0 = 不限）");
      return;
    }
    setAutoFinishError("");
    setSavingAutoFinish(true);
    api
      .setSettings({
        auto_finish_enabled: autoFinishEnabled,
        auto_finish_idle_rounds: idle,
        auto_finish_min_rounds: min,
        auto_finish_coverage_pct: cov,
        auto_finish_max_rounds: max,
      })
      .then((s) => {
        apply(s);
        toast.success("已保存自动收尾设置（下一轮规划生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingAutoFinish(false));
  };

  const saveIntentBudget = () => {
    const tokens = Number(intentBudgetTokens);
    if (!Number.isInteger(tokens) || tokens < 500000 || tokens > 20000000) {
      setIntentBudgetError("意图 token 预算必须在 500000–20000000 之间");
      return;
    }
    setIntentBudgetError("");
    setSavingIntentBudget(true);
    api
      .setSettings({ intent_budget_enabled: intentBudgetEnabled, intent_budget_tokens: tokens })
      .then((s) => {
        apply(s);
        toast.success("已保存意图预算（对之后启动的意图生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingIntentBudget(false));
  };

  const saveCompaction = () => {
    const t = Number(compactionTokens);
    const to = Number(compactionTimeout);
    const m = Number(compactionMembers);
    if (!Number.isInteger(t) || t < 0) {
      setCompactionError("输出预算必须是不小于 0 的整数（0 = 默认）");
      return;
    }
    if (!Number.isInteger(to) || to < 0) {
      setCompactionError("超时必须是不小于 0 的整数秒（0 = 默认）");
      return;
    }
    if (!Number.isInteger(m) || m < 0) {
      setCompactionError("单块节点数必须是不小于 0 的整数（0 = 默认）");
      return;
    }
    setCompactionError("");
    setSavingCompaction(true);
    api
      .setSettings({
        compaction_max_tokens: t,
        compaction_timeout_seconds: to,
        compaction_max_members: m,
      })
      .then((s) => {
        apply(s);
        toast.success("已保存压缩参数（对之后启动的任务生效）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingCompaction(false));
  };

  const savePython = () => {
    setSaving(true);
    api
      .setSettings({ python_interpreter: pyInterp.trim() })
      .then((s) => {
        apply(s);
        toast.success("已保存 Python 解释器配置");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSaving(false));
  };
  const detectPython = () => {
    setSaving(true);
    api
      .detectPython()
      .then((r) => setPyInterp(r.python_interpreter))
      .catch(() => undefined)
      .finally(() => setSaving(false));
  };

  React.useEffect(() => {
    api
      .settings()
      .then(apply)
      .catch(() => undefined)
      .finally(() => setLoaded(true));
    // B10:压缩器模型下拉需要配置列表。best-effort——失败只是少几个选项。
    api
      .llmProfiles()
      .then((ps) => setLlmProfileOpts(ps.map((p) => ({ id: p.id, name: p.name }))))
      .catch(() => setLlmProfileOpts([]));
  }, [apply]);

  // 录制代理死亡态文案：开关开着但代理没起来（多半端口被占）时，标签行就地变红说明后果。
  let trafficState = "已关闭 · 不记录、不注入代理";
  if (trafficCapture) {
    trafficState = trafficProxyAlive
      ? "已开启 · 正在记录流量并注入代理"
      : "已开启 · 录制代理未运行，不会记录流量（释放端口后重启服务恢复）";
  }

  const toggleTraffic = (v: boolean) => {
    setTrafficCapture(v); // optimistic
    setSaving(true);
    api
      .setSettings({ traffic_capture: v })
      .then(apply)
      .catch(() => setTrafficCapture(!v)) // revert on failure
      .finally(() => setSaving(false));
  };

  const toggleInjectPlanner = (v: boolean) => {
    setInjectPlanner(v); // optimistic
    api
      .setSettings({ constraints_inject_planner: v })
      .then(apply)
      .catch(() => setInjectPlanner(!v)); // revert on failure
  };

  const toggleAgentTrafficBinding = (v: boolean) => {
    setAgentTrafficBinding(v);
    setSaving(true);
    api
      .setSettings({ agent_traffic_binding: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "已开启 Agent 自动绑定流量" : "已关闭 Agent 自动绑定流量");
      })
      .catch((e) => {
        setAgentTrafficBinding(!v);
        toast.error(`保存失败：${(e as Error).message}`);
      })
      .finally(() => setSaving(false));
  };

  const toggleInjectWorker = (v: boolean) => {
    setInjectWorker(v); // optimistic
    api
      .setSettings({ constraints_inject_worker: v })
      .then(apply)
      .catch(() => setInjectWorker(!v)); // revert on failure
  };

  const toggleNoaCompaction = (v: boolean) => {
    setNoaCompaction(v); // optimistic
    api
      .setSettings({ noa_compaction: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "已开启 noa 上下文压缩（对之后启动的运行生效）" : "已关闭 noa 上下文压缩（恢复内置压缩）");
      })
      .catch((e) => {
        setNoaCompaction(!v); // revert on failure
        toast.error(`保存失败：${(e as Error).message}`);
      });
  };

  // B10:压缩器钉住的配置，onValueChange 即存（乐观更新）。对之后启动的任务与
  // 运行中任务的下一轮生效——后端会在保存时重建任务 agent 集合。
  const saveCompactorProfile = (v: string) => {
    const prev = compactorProfile;
    setCompactorProfile(v);
    api
      .setSettings({ compactor_profile_id: Number(v) })
      .then((s) => {
        apply(s);
        toast.success(Number(v) > 0 ? "已保存压缩器模型（对之后启动的任务生效）" : "已恢复压缩器跟随规划器");
      })
      .catch((e) => {
        setCompactorProfile(prev); // revert on failure
        toast.error(`保存失败：${(e as Error).message}`);
      });
  };

  // Persist a web-search patch (enable and/or backend). Optimistic with refetch.
  const saveWebSearch = (patch: Partial<Settings>) => {
    setSaving(true);
    api
      .setSettings(patch)
      .then((s) => {
        apply(s);
        toast.success("已保存网络搜索配置");
      })
      .catch((e) => {
        toast.error(`保存失败：${(e as Error).message}`);
        api
          .settings()
          .then(apply)
          .catch(() => undefined);
      })
      .finally(() => setSaving(false));
  };

  const saveBraveKey = () => {
    setSavingKey(true);
    api
      .setSettings({ brave_search_api_key: braveKeyInput })
      .then((s) => {
        apply(s);
        setBraveKeyInput("");
        toast.success("已保存 Brave API Key");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingKey(false));
  };

  const saveTavilyKey = () => {
    setSavingTavilyKey(true);
    api
      .setSettings({ tavily_search_api_key: tavilyKeyInput })
      .then((s) => {
        apply(s);
        setTavilyKeyInput("");
        toast.success("已保存 Tavily API Key");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingTavilyKey(false));
  };

  // IM 接入：按平台保存（密钥留空=不上送即不改动），后端保存即全停重起对应
  // 平台的收发循环；agent_key 每次随保存上送。
  async function saveIM(platform: "feishu" | "dingtalk" | "telegram" | "wecom") {
    const bot: ImBotSettingsInput = { agent_key: imAgent.trim() || "auto" };
    if (platform === "feishu") {
      bot.feishu = {
        enabled: imFeishuOn,
        app_id: imFeishuAppID.trim(),
        ...(imFeishuSecret ? { app_secret: imFeishuSecret } : {}),
      };
    } else if (platform === "dingtalk") {
      bot.dingtalk = {
        enabled: imDingtalkOn,
        client_id: imDingtalkID.trim(),
        ...(imDingtalkSecret ? { client_secret: imDingtalkSecret } : {}),
      };
    } else if (platform === "telegram") {
      bot.telegram = {
        enabled: imTelegramOn,
        proxy: imTelegramProxy.trim(),
        ...(imTelegramToken ? { bot_token: imTelegramToken } : {}),
      };
    } else {
      bot.wecom = {
        enabled: imWecomOn,
        corp_id: imWecomCorpID.trim(),
        agent_id: Number.parseInt(imWecomAgentID, 10) || 0,
        ...(imWecomSecret ? { corp_secret: imWecomSecret } : {}),
        ...(imWecomCallbackToken ? { callback_token: imWecomCallbackToken } : {}),
        ...(imWecomAESKey ? { encoding_aes_key: imWecomAESKey } : {}),
      };
    }
    setSavingIM(platform);
    try {
      const s = await api.setIMBot(bot);
      apply(s);
      setImFeishuSecret("");
      setImDingtalkSecret("");
      setImTelegramToken("");
      setImWecomSecret("");
      setImWecomCallbackToken("");
      setImWecomAESKey("");
      toast.success("已保存 IM 接入配置");
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSavingIM("");
    }
  }

  const saveProxy = () => {
    setSavingProxy(true);
    api
      .setSettings({ web_search_proxy: proxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(proxyInput.trim() ? "已保存出口代理" : "已清除出口代理（改为直连）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingProxy(false));
  };

  const saveGlobalProxy = () => {
    setSavingGlobalProxy(true);
    api
      .setSettings({ global_proxy: globalProxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(globalProxyInput.trim() ? "已保存全局代理" : "已清除全局代理（改为直连）");
      })
      .catch((e) => toast.error(`保存失败：${(e as Error).message}`))
      .finally(() => setSavingGlobalProxy(false));
  };

  // Run a real "test" search ("test") against the CURRENT form values (backend +
  // proxy + entered key), falling back to saved values server-side. Toasts result.
  const runTest = () => {
    setTesting(true);
    api
      .testWebSearch({
        web_search_backend: backend,
        web_search_proxy: proxyInput.trim(),
        brave_search_api_key: braveKeyInput,
        tavily_search_api_key: tavilyKeyInput,
      })
      .then((r) => {
        if (r.ok) toast.success(`搜索测试成功 · ${r.backend} 返回 ${r.count} 条结果`);
        else toast.error(`搜索测试失败：${r.error || "未知错误"}`);
      })
      .catch((e) => toast.error(`搜索测试失败：${(e as Error).message}`))
      .finally(() => setTesting(false));
  };

  // brave-free selected but no key stored and none being entered → tool stays off.
  const braveNeedsKey = webSearch && backend === "brave-free" && !braveKeySet;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-2xl tracking-tight">系统配置</h1>
      </div>

      {/* 多列而非 grid：网络搜索卡片比其余高数倍，且高度随所选后端变化（brave/tavily
 的 key 输入是条件渲染）。grid 会按最高的一张撑满整行、在旁边留下大片空白，
 多列则自动按内容高度平衡填充。卡片间距靠 mb 而非 gap——多列布局下
 column-gap 只管列间距，行间距要由子元素自己给。 */}
      {!loaded ? (
        <div className="columns-1 gap-4 md:gap-6 lg:columns-2">
          <Skeleton className="mb-4 h-44 break-inside-avoid md:mb-6" />
          <Skeleton className="mb-4 h-24 break-inside-avoid md:mb-6" />
          <Skeleton className="mb-4 h-32 break-inside-avoid md:mb-6" />
          <Skeleton className="mb-4 h-24 break-inside-avoid md:mb-6" />
          <Skeleton className="mb-4 h-40 break-inside-avoid md:mb-6" />
        </div>
      ) : (
        <div className="columns-1 gap-4 md:gap-6 lg:columns-2">
          <UpdateCard />

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <RadioTowerIcon className="size-4" />
                流量捕获
              </CardTitle>
              <CardDescription>
                开启后 Agent 的 HTTP 流量经记录代理全量落库并注入流量工具；关闭时不记录。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex items-center justify-between gap-4">
              <Label
                htmlFor="traffic-capture"
                className={cn(
                  "font-normal text-sm",
                  trafficCapture && !trafficProxyAlive ? "text-destructive" : "text-muted-foreground",
                )}
              >
                {trafficState}
              </Label>
              <Switch
                id="traffic-capture"
                checked={trafficCapture}
                disabled={!loaded || saving}
                onCheckedChange={toggleTraffic}
              />
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <RadioTowerIcon className="size-4" />
                Agent 自动绑定流量
              </CardTitle>
              <CardDescription id="agent-traffic-binding-description">
                开启后漏洞报告 Agent 自动关联已有 HTTP 流量，会增加 Token 消耗。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex items-center justify-between gap-4">
              <Label htmlFor="agent-traffic-binding" className="font-normal text-muted-foreground text-sm">
                {agentTrafficBinding ? "已开启 · 会增加 Token 消耗" : "已关闭 · 可继续人工绑定"}
              </Label>
              <Switch
                id="agent-traffic-binding"
                aria-describedby="agent-traffic-binding-description"
                checked={agentTrafficBinding}
                disabled={!loaded || saving}
                onCheckedChange={toggleAgentTrafficBinding}
              />
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <RadioTowerIcon className="size-4" />
                全局代理
              </CardTitle>
              <CardDescription>
                所有 Agent 的目标流量经此代理出网，支持 http / https / socks5，留空直连。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              <Label htmlFor="global-proxy" className="font-normal text-muted-foreground text-sm">
                代理地址
              </Label>
              <div className="flex items-center gap-2">
                <Input
                  id="global-proxy"
                  autoComplete="off"
                  placeholder="socks5://user:pass@host:1080 或 http://host:port（留空=直连）"
                  value={globalProxyInput}
                  disabled={!loaded || savingGlobalProxy}
                  onChange={(e) => setGlobalProxyInput(e.target.value)}
                />
                <Button type="button" onClick={saveGlobalProxy} disabled={!loaded || savingGlobalProxy}>
                  保存
                </Button>
              </div>
              <p className="text-muted-foreground text-xs">
                {globalProxyInput.trim() ? "已配置 · 所有目标流量经此代理出网" : "未配置 · 目标流量直连出网"}
              </p>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <ShieldAlertIcon className="size-4" />
                操作约束注入
              </CardTitle>
              <CardDescription>
                把任务的操作约束拼进对应 Agent 的系统提示，可分别控制规划者与执行者，默认都开。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor="inject-planner" className="font-normal text-muted-foreground text-sm">
                  注入规划者（planner）{injectPlanner ? " · 已开启" : " · 已关闭"}
                </Label>
                <Switch
                  id="inject-planner"
                  checked={injectPlanner}
                  disabled={!loaded}
                  onCheckedChange={toggleInjectPlanner}
                />
              </div>
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor="inject-worker" className="font-normal text-muted-foreground text-sm">
                  注入执行者（worker）{injectWorker ? " · 已开启" : " · 已关闭"}
                </Label>
                <Switch
                  id="inject-worker"
                  checked={injectWorker}
                  disabled={!loaded}
                  onCheckedChange={toggleInjectWorker}
                />
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <FlaskConicalIcon className="size-4" />
                实验功能
              </CardTitle>
              <CardDescription>尚在验证中的机制，默认关闭；切换对之后启动的运行生效。</CardDescription>
            </CardHeader>
            <CardContent className="flex items-center justify-between gap-4">
              <Label htmlFor="noa-compaction" className="font-normal text-muted-foreground text-sm">
                noa 上下文压缩{noaCompaction ? " · 已开启" : " · 已关闭"}
              </Label>
              <Switch
                id="noa-compaction"
                checked={noaCompaction}
                disabled={!loaded}
                onCheckedChange={toggleNoaCompaction}
              />
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <SearchIcon className="size-4" />
                网络搜索
              </CardTitle>
              <CardDescription>总开关 + 来源配置；开启后可在各 Agent 配置里单独启用 web_search。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor="web-search" className="font-normal text-muted-foreground text-sm">
                  {webSearch ? "总开关已开启 · 可在各 Agent 配置里单独启用" : "已关闭 · 各 Agent 无法启用网络搜索"}
                </Label>
                <Switch
                  id="web-search"
                  checked={webSearch}
                  disabled={!loaded || saving}
                  onCheckedChange={(v) => {
                    setWebSearch(v); // optimistic
                    saveWebSearch({ web_search_enabled: v });
                  }}
                />
              </div>

              {webSearch && (
                <div className="flex items-center justify-between gap-4">
                  <Label className="font-normal text-muted-foreground text-sm">搜索来源</Label>
                  <Select
                    value={backend}
                    disabled={!loaded || saving}
                    onValueChange={(v) => {
                      setBackend(v); // optimistic
                      saveWebSearch({ web_search_backend: v });
                    }}
                  >
                    <SelectTrigger className="w-48 shrink-0">
                      <SelectValue placeholder="选择来源" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ddgs">DuckDuckGo（ddgs · 免费无 Key）</SelectItem>
                      <SelectItem value="brave-free">Brave（免费版 · 需 Key）</SelectItem>
                      <SelectItem value="tavily">Tavily（需 Key）</SelectItem>
                      <SelectItem value="deepseek">DeepSeek（官方）</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}

              {webSearch && backend === "deepseek" && (
                <div className="flex flex-col gap-2 bg-muted/30 p-3">
                  <p className="font-medium text-sm">DeepSeek 官方联网搜索</p>
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    复用当前激活的 LLM 配置（须为 DeepSeek 官方模型 + anthropic 协议），服务端执行、按次消耗
                    Token，结果仅含标题与链接。
                  </p>
                </div>
              )}

              {webSearch && backend === "brave-free" && (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="brave-key" className="font-normal text-muted-foreground text-sm">
                    Brave Search API Key
                    {braveKeySet && <span className="ml-2 text-success text-xs">已配置</span>}
                  </Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="brave-key"
                      type="password"
                      autoComplete="off"
                      placeholder={braveKeySet ? "已配置（留空则不变）" : "输入 Brave API Key"}
                      value={braveKeyInput}
                      disabled={!loaded || savingKey}
                      onChange={(e) => setBraveKeyInput(e.target.value)}
                    />
                    <Button
                      type="button"
                      onClick={saveBraveKey}
                      disabled={!loaded || savingKey || braveKeyInput.trim() === ""}
                    >
                      保存
                    </Button>
                  </div>
                  {braveNeedsKey && (
                    <p className="text-warning text-xs">
                      已选择 Brave 但尚未配置 Key —— 在保存 Key 之前，搜索工具不会启用。
                    </p>
                  )}
                  <p className="text-muted-foreground text-xs">
                    免费版额度约 2,000 次/月。前往 https://brave.com/search/api/ 获取 Key。
                  </p>
                </div>
              )}

              {webSearch && backend === "tavily" && (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="tavily-key" className="font-normal text-muted-foreground text-sm">
                    Tavily Search API Key
                    {tavilyKeySet && <span className="ml-2 text-success text-xs">已配置</span>}
                  </Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="tavily-key"
                      type="password"
                      autoComplete="off"
                      placeholder={tavilyKeySet ? "已配置（留空则不变）" : "输入 Tavily API Key（tvly-…）"}
                      value={tavilyKeyInput}
                      disabled={!loaded || savingTavilyKey}
                      onChange={(e) => setTavilyKeyInput(e.target.value)}
                    />
                    <Button
                      type="button"
                      onClick={saveTavilyKey}
                      disabled={!loaded || savingTavilyKey || tavilyKeyInput.trim() === ""}
                    >
                      保存
                    </Button>
                  </div>
                  {webSearch && backend === "tavily" && !tavilyKeySet && (
                    <p className="text-warning text-xs">
                      已选择 Tavily 但尚未配置 Key —— 在保存 Key 之前，搜索工具不会启用。
                    </p>
                  )}
                  <p className="text-muted-foreground text-xs">前往 https://tavily.com 注册并获取 API Key。</p>
                </div>
              )}

              {webSearch && (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="ws-proxy" className="font-normal text-muted-foreground text-sm">
                    出口代理（可选）
                  </Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="ws-proxy"
                      autoComplete="off"
                      placeholder="http://host:port 或 socks5://host:port（留空=直连）"
                      value={proxyInput}
                      disabled={!loaded || savingProxy}
                      onChange={(e) => setProxyInput(e.target.value)}
                    />
                    <Button type="button" onClick={saveProxy} disabled={!loaded || savingProxy}>
                      保存
                    </Button>
                  </div>
                  <p className="text-muted-foreground text-xs">
                    独立出口代理，仅用于访问搜索端点（VPN/SOCKS 等）。与记录流量的 MITM
                    代理无关；网络不通时经此代理访问。
                  </p>
                </div>
              )}

              {webSearch && (
                <div className="flex items-center justify-between gap-4 border-t pt-4">
                  <p className="text-muted-foreground text-xs">
                    用当前配置（来源 + 代理 + Key）实际搜索一次「test」，验证是否可用。
                  </p>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={runTest}
                    disabled={!loaded || testing}
                    className="shrink-0"
                  >
                    {testing ? "测试中…" : "测试搜索"}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <RadioTowerIcon className="size-4" />
                自定义脚本 · Python 解释器
              </CardTitle>
              <CardDescription>自定义 script 类型工具用它跑 Python，留空自动检测。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <Input
                  className="font-mono text-sm"
                  placeholder="/usr/bin/python3（留空=自动检测）"
                  value={pyInterp}
                  disabled={!loaded || saving}
                  onChange={(e) => setPyInterp(e.target.value)}
                />
                <Button variant="outline" onClick={detectPython} disabled={!loaded || saving}>
                  重新检测
                </Button>
                <Button onClick={savePython} disabled={!loaded || saving}>
                  保存
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <CpuIcon className="size-4" />
                工作并发 · Work Agent 数
              </CardTitle>
              <CardDescription>每个任务并发运行的工作 agent 数，对之后启动的任务生效。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <Input
                  type="number"
                  min={1}
                  className="w-32 font-mono text-sm"
                  placeholder="3"
                  value={workers}
                  disabled={!loaded || savingWorkers}
                  onChange={(e) => {
                    setWorkers(e.target.value);
                    setWorkersError("");
                  }}
                />
                <Button onClick={saveWorkers} disabled={!loaded || savingWorkers}>
                  保存
                </Button>
              </div>
              {workersError && <p className="text-destructive text-xs">{workersError}</p>}
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <TimerResetIcon className="size-4" />
                任务自动收尾
              </CardTitle>
              <CardDescription>连续无新增、覆盖率达标或达到最大轮数时自动收尾，原因写入活动流。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex items-center justify-between gap-4">
                <div className="flex flex-col">
                  <Label htmlFor="auto-finish-enabled" className="text-sm">
                    启用自动收尾
                  </Label>
                  <span className="text-muted-foreground text-xs">关闭后只能靠任务超时或目标闭环结束</span>
                </div>
                <Switch
                  id="auto-finish-enabled"
                  checked={autoFinishEnabled}
                  disabled={!loaded || savingAutoFinish}
                  onCheckedChange={setAutoFinishEnabled}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="flex flex-col gap-1 text-sm">
                  <span>连续无新增轮数（2–20）</span>
                  <Input
                    type="number"
                    min={2}
                    max={20}
                    className="w-40 font-mono text-sm"
                    value={autoFinishIdle}
                    disabled={!loaded || savingAutoFinish}
                    onChange={(e) => {
                      setAutoFinishIdle(e.target.value);
                      setAutoFinishError("");
                    }}
                  />
                </label>
                <label className="flex flex-col gap-1 text-sm">
                  <span>最少规划轮数（1–50）</span>
                  <Input
                    type="number"
                    min={1}
                    max={50}
                    className="w-40 font-mono text-sm"
                    value={autoFinishMin}
                    disabled={!loaded || savingAutoFinish}
                    onChange={(e) => {
                      setAutoFinishMin(e.target.value);
                      setAutoFinishError("");
                    }}
                  />
                </label>
                <label className="flex flex-col gap-1 text-sm">
                  <span>覆盖率阈值 %（0 = 关闭）</span>
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    className="w-40 font-mono text-sm"
                    value={autoFinishCoverage}
                    disabled={!loaded || savingAutoFinish}
                    onChange={(e) => {
                      setAutoFinishCoverage(e.target.value);
                      setAutoFinishError("");
                    }}
                  />
                </label>
                <label className="flex flex-col gap-1 text-sm">
                  <span>最大规划轮数（0 = 不限）</span>
                  <Input
                    type="number"
                    min={0}
                    max={500}
                    className="w-40 font-mono text-sm"
                    value={autoFinishMax}
                    disabled={!loaded || savingAutoFinish}
                    onChange={(e) => {
                      setAutoFinishMax(e.target.value);
                      setAutoFinishError("");
                    }}
                  />
                </label>
              </div>
              {autoFinishError && <p className="text-destructive text-xs">{autoFinishError}</p>}
              <div>
                <Button onClick={saveAutoFinish} disabled={!loaded || savingAutoFinish}>
                  {savingAutoFinish ? "保存中…" : "保存"}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <GaugeIcon className="size-4" />
                意图级软预算与重复调用拦截
              </CardTitle>
              <CardDescription>单条意图累计 token 到预算后注入收尾提醒，重复调用拦截随此开关联动。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex items-center justify-between gap-4">
                <div className="flex flex-col">
                  <Label htmlFor="intent-budget-enabled" className="text-sm">
                    启用意图预算提醒
                  </Label>
                  <span className="text-muted-foreground text-xs">关闭后不注入提醒，也不做重复调用拦截</span>
                </div>
                <Switch
                  id="intent-budget-enabled"
                  checked={intentBudgetEnabled}
                  disabled={!loaded || savingIntentBudget}
                  onCheckedChange={setIntentBudgetEnabled}
                />
              </div>
              <label className="flex flex-col gap-1 text-sm">
                <span>单意图 token 预算（500000–20000000）</span>
                <Input
                  type="number"
                  min={500000}
                  max={20000000}
                  step={100000}
                  className="w-48 font-mono text-sm"
                  value={intentBudgetTokens}
                  disabled={!loaded || savingIntentBudget}
                  onChange={(e) => {
                    setIntentBudgetTokens(e.target.value);
                    setIntentBudgetError("");
                  }}
                />
              </label>
              {intentBudgetError && <p className="text-destructive text-xs">{intentBudgetError}</p>}
              <div>
                <Button onClick={saveIntentBudget} disabled={!loaded || savingIntentBudget}>
                  {savingIntentBudget ? "保存中…" : "保存"}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <CpuIcon className="size-4" />
                上下文压缩参数
              </CardTitle>
              <CardDescription>
                冷节点压缩的输出预算、单次超时与单块节点数，填 0 用默认值，对之后启动的任务生效。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Label htmlFor="compaction-tokens" className="w-40 text-sm">
                  输出预算 (token)
                </Label>
                <Input
                  id="compaction-tokens"
                  type="number"
                  min={0}
                  step={1024}
                  className="w-40 font-mono text-sm"
                  placeholder="0 = 默认 65536"
                  value={compactionTokens}
                  disabled={!loaded || savingCompaction}
                  onChange={(e) => {
                    setCompactionTokens(e.target.value);
                    setCompactionError("");
                  }}
                />
                <Label htmlFor="compaction-timeout" className="w-40 text-sm">
                  单次超时 (秒)
                </Label>
                <Input
                  id="compaction-timeout"
                  type="number"
                  min={0}
                  step={60}
                  className="w-40 font-mono text-sm"
                  placeholder="0 = 默认 1200"
                  value={compactionTimeout}
                  disabled={!loaded || savingCompaction}
                  onChange={(e) => {
                    setCompactionTimeout(e.target.value);
                    setCompactionError("");
                  }}
                />
                <Label htmlFor="compaction-members" className="w-40 text-sm">
                  单块节点数上限
                </Label>
                <Input
                  id="compaction-members"
                  type="number"
                  min={0}
                  className="w-40 font-mono text-sm"
                  placeholder="0 = 默认 6"
                  value={compactionMembers}
                  disabled={!loaded || savingCompaction}
                  onChange={(e) => {
                    setCompactionMembers(e.target.value);
                    setCompactionError("");
                  }}
                />
                <Button onClick={saveCompaction} disabled={!loaded || savingCompaction}>
                  保存
                </Button>
              </div>
              {compactionError && <p className="text-destructive text-xs">{compactionError}</p>}
              {/* B10:压缩器模型。规划器跑贵模型时，把机械的冷节点压缩钉在便宜模型上省钱;
 一次一发的设计让压缩对速度远比对话敏感，低价高速模型反而是更搭的选型。 */}
              <div className="flex flex-wrap items-center gap-2">
                <Label htmlFor="compactor-profile" className="w-40 text-sm">
                  压缩器模型
                </Label>
                <Select value={compactorProfile} onValueChange={saveCompactorProfile}>
                  <SelectTrigger id="compactor-profile" className="w-72">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="0">跟随规划器（默认）</SelectItem>
                    {llmProfileOpts.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <span className="text-muted-foreground text-xs">
                  冷节点压缩是后台的一次性调用，适合钉在低价模型上省钱。钉住的配置被删/无 Key
                  时自动落回跟随规划器；额度耗尽按绑定语义直接失败（换配置或改回「跟随规划器」）。
                </span>
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <MessageSquareIcon className="size-4" />
                IM 机器人
              </CardTitle>
              <CardDescription>
                在飞书 / 钉钉 / Telegram / 企业微信里直接对话与执行指令，保存即重起对应平台收发循环。
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col divide-y">
              <div className="flex items-center gap-3 pb-4">
                <Label htmlFor="im-agent" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                  对话 Agent
                </Label>
                <Input
                  id="im-agent"
                  value={imAgent}
                  onChange={(e) => setImAgent(e.target.value)}
                  placeholder="auto"
                  className="h-8 w-40 font-mono"
                />
                <span className="text-muted-foreground text-xs">IM 新会话使用的 agent key，随下方任一保存生效</span>
              </div>

              <div className="flex flex-col gap-3 py-4">
                <div className="flex items-center justify-between gap-4">
                  <Label htmlFor="im-feishu-on" className="text-sm font-normal text-muted-foreground">
                    飞书{imFeishuOn ? " · 已开启" : " · 已关闭"}
                  </Label>
                  <Switch
                    id="im-feishu-on"
                    checked={imFeishuOn}
                    disabled={!loaded || savingIM !== ""}
                    onCheckedChange={setImFeishuOn}
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-2">
                    <Label
                      htmlFor="im-feishu-appid"
                      className="w-24 shrink-0 text-sm font-normal text-muted-foreground"
                    >
                      App ID
                    </Label>
                    <Input
                      id="im-feishu-appid"
                      value={imFeishuAppID}
                      onChange={(e) => setImFeishuAppID(e.target.value)}
                      placeholder="cli_xxx"
                      className="h-8 font-mono"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label
                      htmlFor="im-feishu-secret"
                      className="w-24 shrink-0 text-sm font-normal text-muted-foreground"
                    >
                      App Secret
                    </Label>
                    <Input
                      id="im-feishu-secret"
                      type="password"
                      autoComplete="off"
                      value={imFeishuSecret}
                      onChange={(e) => setImFeishuSecret(e.target.value)}
                      placeholder={imFeishuSecretSet ? "已配置（留空则不变）" : ""}
                      className="h-8"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!loaded || savingIM !== ""}
                    onClick={() => void saveIM("feishu")}
                  >
                    保存飞书
                  </Button>
                </div>
              </div>

              <div className="flex flex-col gap-3 py-4">
                <div className="flex items-center justify-between gap-4">
                  <Label htmlFor="im-dingtalk-on" className="text-sm font-normal text-muted-foreground">
                    钉钉{imDingtalkOn ? " · 已开启" : " · 已关闭"}
                  </Label>
                  <Switch
                    id="im-dingtalk-on"
                    checked={imDingtalkOn}
                    disabled={!loaded || savingIM !== ""}
                    onCheckedChange={setImDingtalkOn}
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-ding-id" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      Client ID
                    </Label>
                    <Input
                      id="im-ding-id"
                      value={imDingtalkID}
                      onChange={(e) => setImDingtalkID(e.target.value)}
                      placeholder="AppKey"
                      className="h-8 font-mono"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-ding-secret" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      Client Secret
                    </Label>
                    <Input
                      id="im-ding-secret"
                      type="password"
                      autoComplete="off"
                      value={imDingtalkSecret}
                      onChange={(e) => setImDingtalkSecret(e.target.value)}
                      placeholder={imDingtalkSecretSet ? "已配置（留空则不变）" : ""}
                      className="h-8"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!loaded || savingIM !== ""}
                    onClick={() => void saveIM("dingtalk")}
                  >
                    保存钉钉
                  </Button>
                </div>
              </div>

              <div className="flex flex-col gap-3 py-4">
                <div className="flex items-center justify-between gap-4">
                  <Label htmlFor="im-telegram-on" className="text-sm font-normal text-muted-foreground">
                    Telegram{imTelegramOn ? " · 已开启" : " · 已关闭"}
                  </Label>
                  <Switch
                    id="im-telegram-on"
                    checked={imTelegramOn}
                    disabled={!loaded || savingIM !== ""}
                    onCheckedChange={setImTelegramOn}
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-tg-token" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      Bot Token
                    </Label>
                    <Input
                      id="im-tg-token"
                      type="password"
                      autoComplete="off"
                      value={imTelegramToken}
                      onChange={(e) => setImTelegramToken(e.target.value)}
                      placeholder={imTelegramTokenSet ? "已配置（留空则不变）" : "123456:ABC-DEF…"}
                      className="h-8 font-mono"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-tg-proxy" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      出口代理
                    </Label>
                    <Input
                      id="im-tg-proxy"
                      value={imTelegramProxy}
                      onChange={(e) => setImTelegramProxy(e.target.value)}
                      placeholder="http://127.0.0.1:7897（空=直连）"
                      className="h-8 font-mono"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!loaded || savingIM !== ""}
                    onClick={() => void saveIM("telegram")}
                  >
                    保存 Telegram
                  </Button>
                </div>
              </div>

              <div className="flex flex-col gap-3 pt-4">
                <div className="flex items-center justify-between gap-4">
                  <Label htmlFor="im-wecom-on" className="text-sm font-normal text-muted-foreground">
                    企业微信{imWecomOn ? " · 已开启" : " · 已关闭"}
                  </Label>
                  <Switch
                    id="im-wecom-on"
                    checked={imWecomOn}
                    disabled={!loaded || savingIM !== ""}
                    onCheckedChange={setImWecomOn}
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-wecom-corp" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      Corp ID
                    </Label>
                    <Input
                      id="im-wecom-corp"
                      value={imWecomCorpID}
                      onChange={(e) => setImWecomCorpID(e.target.value)}
                      className="h-8 font-mono"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-wecom-agent" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      AgentID
                    </Label>
                    <Input
                      id="im-wecom-agent"
                      value={imWecomAgentID}
                      onChange={(e) => setImWecomAgentID(e.target.value)}
                      placeholder="1000002"
                      className="h-8 font-mono"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label
                      htmlFor="im-wecom-secret"
                      className="w-24 shrink-0 text-sm font-normal text-muted-foreground"
                    >
                      应用 Secret
                    </Label>
                    <Input
                      id="im-wecom-secret"
                      type="password"
                      autoComplete="off"
                      value={imWecomSecret}
                      onChange={(e) => setImWecomSecret(e.target.value)}
                      placeholder={imWecomSecretSet ? "已配置（留空则不变）" : ""}
                      className="h-8"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-wecom-token" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      回调 Token
                    </Label>
                    <Input
                      id="im-wecom-token"
                      type="password"
                      autoComplete="off"
                      value={imWecomCallbackToken}
                      onChange={(e) => setImWecomCallbackToken(e.target.value)}
                      placeholder={imWecomCallbackTokenSet ? "已配置（留空则不变）" : ""}
                      className="h-8"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Label htmlFor="im-wecom-aes" className="w-24 shrink-0 text-sm font-normal text-muted-foreground">
                      EncodingAESKey
                    </Label>
                    <Input
                      id="im-wecom-aes"
                      type="password"
                      autoComplete="off"
                      value={imWecomAESKey}
                      onChange={(e) => setImWecomAESKey(e.target.value)}
                      placeholder={imWecomAESKeySet ? "已配置（留空则不变）" : "43 位"}
                      className="h-8"
                    />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Label className="w-24 shrink-0 text-sm font-normal text-muted-foreground">回调地址</Label>
                  <code className="text-muted-foreground min-w-0 truncate font-mono text-xs">
                    {imWecomBaseURLSet
                      ? imWecomCallbackURL
                      : "先在「漏洞推送」里设置回链地址（notify_public_base_url）"}
                  </code>
                </div>
                <div className="flex justify-end">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!loaded || savingIM !== ""}
                    onClick={() => void saveIM("wecom")}
                  >
                    保存企业微信
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4 break-inside-avoid md:mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <KeyboardIcon className="size-4" />
                会话输入框发送键位
              </CardTitle>
              <CardDescription>对话页与任务详情的会话输入框共用，选择后立即生效。</CardDescription>
            </CardHeader>
            <CardContent className="flex items-center justify-between gap-4">
              <Label htmlFor="chat-send-mode" className="font-normal text-muted-foreground text-sm">
                发送方式
              </Label>
              <Select value={sendMode} onValueChange={(v) => setChatSendMode(v as ChatSendMode)}>
                <SelectTrigger id="chat-send-mode" className="w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CHAT_SEND_MODE_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
