"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { api } from "@/lib/api";
import type { HostInstallSources, InstallSourcePreset } from "@/lib/types";

const sourceNames: { id: InstallSourcePreset; label: string }[] = [
  { id: "", label: "系统默认" },
  { id: "tencent", label: "腾讯云镜像" },
  { id: "tuna", label: "清华大学 TUNA 镜像" },
];

const publicRepoPattern = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/([A-Za-z0-9._-]+)$/;

const packageManagers = [
  ["apt", "APT（Debian / Ubuntu / Kali）"],
  ["pypi", "PyPI（pip / pipx）"],
] as const;

export function InstallSources({
  sources,
  supported,
  onSaved,
}: {
  sources: HostInstallSources;
  supported: boolean;
  onSaved: (sources: HostInstallSources) => void;
}) {
  const [draft, setDraft] = useState(sources);
  const [saving, setSaving] = useState(false);
  const [gitSource, setGitSource] = useState("github");
  const [repoInput, setRepoInput] = useState("");
  const { apt, pypi } = sources;
  useEffect(() => setDraft({ apt, pypi }), [apt, pypi]);

  const repo = repoInput.trim().replace(/\/$/, "");
  const repoName = publicRepoPattern.exec(repo)?.[1];
  const gitPrefix = gitSource === "gh-proxy" ? "https://gh-proxy.cn/github/" : "";
  const cloneURL = repoName && repoName !== "." && repoName !== ".."
    ? `${gitPrefix}${repo}${repo.endsWith(".git") ? "" : ".git"}`
    : "";
  const dirty = draft.apt !== apt || draft.pypi !== pypi;
  // Allow recovering saved selections after a helper downgrade.
  const canSave = supported || (!draft.apt && !draft.pypi);

  async function save() {
    setSaving(true);
    try {
      onSaved(await api.hostenvSaveSources(draft));
      toast.success("安装源已保存");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存安装源失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section aria-labelledby="install-sources-heading" className="flex flex-col gap-3 rounded-lg border bg-muted/30 p-3">
      <h2 id="install-sources-heading" className="font-medium text-sm">安装源</h2>
      <p className="text-muted-foreground text-xs">
        APT 和 PyPI 可分别选择镜像，保存后对新建的工具安装任务生效。装机代理可单独设置。
      </p>
      <div className="flex flex-wrap items-end gap-3">
        {packageManagers.map(([key, label]) => (
          <div key={key} className="flex flex-col gap-1.5">
            <Label htmlFor={`install-source-${key}`} className="text-xs">{label}</Label>
            <NativeSelect
              id={`install-source-${key}`}
              value={draft[key]}
              disabled={saving || (!supported && !draft[key])}
              onChange={(event) => setDraft({ ...draft, [key]: event.target.value as InstallSourcePreset })}
            >
              {sourceNames.map(({ id, label }) => (
                <NativeSelectOption key={id} value={id} disabled={!supported && id !== ""}>{label}</NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
        ))}
        <Button type="button" size="sm" onClick={save} disabled={!dirty || saving || !canSave}>
          {saving ? "保存中…" : "保存安装源"}
        </Button>
      </div>
      {!supported && (
        <p className="text-muted-foreground text-xs">选择 APT 或 PyPI 镜像需要在线且支持安装源选项的宿主助手。</p>
      )}
      <div className="flex flex-col gap-2 border-t pt-3">
        <div className="flex flex-wrap items-center gap-2">
          <Label htmlFor="install-source-git" className="text-xs">手动 Git 下载</Label>
          <NativeSelect id="install-source-git" value={gitSource} onChange={(event) => setGitSource(event.target.value)}>
            <NativeSelectOption value="github">GitHub 原站</NativeSelectOption>
            <NativeSelectOption value="gh-proxy">gh-proxy.cn</NativeSelectOption>
          </NativeSelect>
        </div>
        <Input
          aria-label="公开 GitHub 仓库地址"
          placeholder="https://github.com/owner/repo.git"
          value={repoInput}
          onChange={(event) => setRepoInput(event.target.value)}
          className="font-mono text-xs"
        />
        {repoInput.trim() && (cloneURL ? (
          <Input aria-label="Git 克隆地址" value={cloneURL} readOnly onFocus={(event) => event.target.select()} className="font-mono text-xs" />
        ) : (
          <p className="text-muted-foreground text-xs">请输入公开仓库的 GitHub HTTPS 地址。</p>
        ))}
        <p className="text-muted-foreground text-xs">将生成的地址用于手动克隆。第三方加速仅限公开仓库。</p>
      </div>
    </section>
  );
}
