"use client";

import { PlusIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { AssetInterceptKind, AssetInterceptRuleInput } from "@/lib/types";

// 下拉用全站统一的 shadcn Select（Radix 弹层）。这个编辑器用在 Sheet 抽屉内——
// Radix DismissableLayer 分层保证弹层内点击不算抽屉的「点击外部」，不会误关抽屉。
export const ASSET_INTERCEPT_KIND_OPTIONS: {
  value: AssetInterceptKind;
  label: string;
  placeholder: string;
}[] = [
  { value: "exact_domain", label: "域名（全等）", placeholder: "example.gov.cn" },
  { value: "exact_ip", label: "IP（全等）", placeholder: "203.0.113.10" },
  { value: "exact_url", label: "URL（全等）", placeholder: "https://example.com/login" },
  { value: "fuzzy_domain", label: "域名（模糊）", placeholder: ".gov.cn" },
  { value: "fuzzy_ip", label: "IP（模糊）", placeholder: "203.0.113." },
  { value: "fuzzy_url", label: "URL（模糊）", placeholder: "/admin" },
  { value: "cidr", label: "CIDR 网段", placeholder: "192.168.0.0/16" },
];

// AssetInterceptRulesEditor 是「拦截/允许规则」的受控多行编辑区（拦截block/允许allow +
// 类型 + 匹配内容 + 备注），不自带持久化——由父组件决定何时提交。
export function AssetInterceptRulesEditor({
  value,
  onChange,
}: {
  value: AssetInterceptRuleInput[];
  onChange: (v: AssetInterceptRuleInput[]) => void;
}) {
  function update(i: number, patch: Partial<AssetInterceptRuleInput>) {
    onChange(value.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  }
  function remove(i: number) {
    onChange(value.filter((_, idx) => idx !== i));
  }
  function add() {
    onChange([...value, { action: "block", kind: "fuzzy_domain", pattern: "", note: "", enabled: true }]);
  }
  return (
    <div className="grid gap-2">
      {value.map((r, i) => {
        const ph = ASSET_INTERCEPT_KIND_OPTIONS.find((o) => o.value === r.kind)?.placeholder ?? "";
        return (
          // biome-ignore lint/suspicious/noArrayIndexKey: 行无稳定 id，按索引受控即可
          <div key={i} className="flex items-center gap-2">
            <Select value={r.action} onValueChange={(v) => update(i, { action: v as "block" | "allow" })}>
              <SelectTrigger size="sm" className="w-[84px] shrink-0">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="block">拦截</SelectItem>
                <SelectItem value="allow">允许</SelectItem>
              </SelectContent>
            </Select>
            <Select value={r.kind} onValueChange={(v) => update(i, { kind: v as AssetInterceptKind })}>
              <SelectTrigger size="sm" className="w-[120px] shrink-0">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {ASSET_INTERCEPT_KIND_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              className="flex-1"
              placeholder={ph}
              value={r.pattern}
              onChange={(e) => update(i, { pattern: e.target.value })}
            />
            <Input
              className="w-[120px] shrink-0"
              placeholder="备注（可选）"
              value={r.note}
              onChange={(e) => update(i, { note: e.target.value })}
            />
            <Button
              type="button"
              size="icon"
              variant="ghost"
              className="size-8 shrink-0 text-destructive hover:text-destructive"
              onClick={() => remove(i)}
              aria-label="删除该行"
            >
              <Trash2Icon className="size-4" />
            </Button>
          </div>
        );
      })}
      <Button type="button" size="sm" variant="outline" className="w-fit" onClick={add}>
        <PlusIcon data-icon="inline-start" className="size-4" /> 添加一条
      </Button>
    </div>
  );
}
