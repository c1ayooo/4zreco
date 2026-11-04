# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/4zreco。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out internal/server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/4zreco ./cmd/4zreco
#   docker build -t 4zreco:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
      imagemagick libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# nuclei(漏洞模板扫描引擎,配合 /app/nuclei-templates 情报模板库):
# 官方 release 单二进制按架构下载,模板树由 4zreco 的 vulnintel 同步器维护
# (git clone --depth 1 到 /app/nuclei-templates,每轮同步 git pull 更新)。
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) nuclei_arch="linux_amd64" ;; \
      arm64) nuclei_arch="linux_arm64" ;; \
      *) echo "unsupported arch: $arch"; exit 1 ;; \
    esac; \
    nuclei_ver="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name)"; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/${nuclei_ver}/nuclei_${nuclei_ver#v}_${nuclei_arch}.zip" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei && install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && nuclei -version && rm -rf /tmp/nuclei /tmp/nuclei.zip
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/4zreco 或 dist/arm64/4zreco）
COPY dist/${TARGETARCH}/4zreco /app/4zreco
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 4zreco —— docker stop 只把信号发给 PID 1，
# 不转发的话 4zreco 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/4zreco /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
