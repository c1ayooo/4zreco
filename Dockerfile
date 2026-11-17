# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：装全内置工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/4zreco。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out internal/server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/4zreco ./cmd/4zreco
#   CGO_ENABLED=0 GOARCH=amd64 go build -o dist/amd64/4zreco-hostd ./cmd/4zreco-hostd
#   docker build -t 4zreco:local .
# kerbrute / waybackurls 上游不发 linux/arm64 资产，用 Go 现场编译补齐
# （builder 走目标平台的 golang 镜像，产物架构自动正确；QEMU 下只编译这两个
# 小工具，构建时间增加可控）。
FROM golang:1.26-bookworm AS gobuild
ENV CGO_ENABLED=0 GOBIN=/go/bin
RUN go install github.com/ropnop/kerbrute@v1.0.3 \
    && go install github.com/tomnomnom/waybackurls@v0.1.0

FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 构建源（默认官方；国内/受限网络用 --build-arg 覆盖）：
#   docker build --build-arg DEBIAN_MIRROR=mirrors.aliyun.com \
#                --build-arg PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ .
ARG DEBIAN_MIRROR=deb.debian.org
ARG DEBIAN_SECURITY_MIRROR=deb.debian.org
ARG NODESOURCE_URL=https://deb.nodesource.com/setup_20.x
# 注：NodeSource 没有官方镜像替换；受限网络可用 --build-arg NODESOURCE_URL=<可信镜像的 setup 脚本地址>
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_INDEX_URL=${PIP_INDEX_URL}
RUN if [ "$DEBIAN_MIRROR" != "deb.debian.org" ]; then \
      sed -i "s|deb.debian.org|$DEBIAN_MIRROR|g; s|security.debian.org|$DEBIAN_SECURITY_MIRROR|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
      sed -i "s|deb.debian.org|$DEBIAN_MIRROR|g; s|security.debian.org|$DEBIAN_SECURITY_MIRROR|g" /etc/apt/sources.list; \
    fi
# 基础件 + 渗透工具组。渗透组逐包容错：Debian bookworm 源没有的包（如 nikto，
# Kali 源才有）跳过不阻断构建，运行期「宿主环境」体检页会如实显示缺失；
# gobuster/gitleaks 等更新更全的版本走 docker/install-tools.sh 的 GitHub release。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates ripgrep curl wget vim git jq unzip \
         dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
         imagemagick libreoffice-writer libreoffice-calc libreoffice-impress poppler-utils \
    && for pkg in masscan sqlmap hydra whatweb nikto ffuf john python3-impacket socat proxychains4; do \
         apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 \
         || echo "[warn] apt 包不可用，跳过: $pkg"; \
       done \
    && curl -fsSL "$NODESOURCE_URL" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# kerbrute/waybackurls（上游无 arm64 资产，builder 现场编译）
COPY --from=gobuild /go/bin/kerbrute /usr/local/bin/kerbrute
COPY --from=gobuild /go/bin/waybackurls /usr/local/bin/waybackurls
# nuclei(漏洞模板扫描引擎,配合 /app/nuclei-templates 情报模板库):
# 官方 release 单二进制按架构下载,模板树由 4zreco 的 vulnintel 同步器维护
# (git clone --depth 1 到 /app/nuclei-templates,每轮同步 git pull 更新)。
# compose 部署时该目录以 bind mount 挂到宿主（见 docker-compose.yml），容器
# 重建/升级不重下 100-200MB 模板——镜像内这层只做首次启动前的兜底。
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) nuclei_arch="linux_amd64" ;; \
      arm64) nuclei_arch="linux_arm64" ;; \
      *) echo "unsupported arch: $arch"; exit 1 ;; \
    esac; \
    # 版本解析双通道：GitHub API 对 CI runner 共享 IP 经常 403 限流（上游
    # v0.4.54 构建实测挂在这），后备走 releases/latest 的 302 Location
    # ——浏览器同款路径，不吃 API 配额。api github 域名也要加超时防挂死。
    nuclei_ver="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name)" || nuclei_ver=""; \
    [ -n "$nuclei_ver" ] && [ "$nuclei_ver" != "null" ] || \
      nuclei_ver="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 -o /dev/null -w '%{url_effective}' https://github.com/projectdiscovery/nuclei/releases/latest | sed 's|.*/tag/||')"; \
    [ -n "$nuclei_ver" ] || { echo "cannot resolve nuclei version"; exit 1; }; \
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "https://github.com/projectdiscovery/nuclei/releases/download/${nuclei_ver}/nuclei_${nuclei_ver#v}_${nuclei_arch}.zip" -o /tmp/nuclei.zip; \
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
# 特权安装助手：容器内以 root 常驻 unix socket，「宿主环境」页可运行期装/重装工具；
# 首次启动还用它后台预装 catalog 缺失项（见 docker/docker-entrypoint.sh）。
COPY dist/${TARGETARCH}/4zreco-hostd /app/4zreco-hostd
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 4zreco —— docker stop 只把信号发给 PID 1，
# 不转发的话 4zreco 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/4zreco /app/4zreco-hostd /app/start.sh
COPY skills/ /app/skills/
# 公文字体：docx→PDF 渲染需要（docx 内部已 embed 三字体，Word/WPS 不依赖系统
# 字体；但 LibreOffice 转 PDF 读系统字体，新机器不装会 fallback）。二进制形态
# 从仓库 raw 下载（install.sh install_fonts）；镜像直接 COPY 仓库内文件。
COPY internal/report/fonts/ /usr/share/fonts/gongwen/
RUN fc-cache -f /usr/share/fonts/gongwen >/dev/null 2>&1 || true
# 内置渗透工具与字典（对齐 install.sh --with-tools；详见 docker/install-tools.sh）：
# projectdiscovery 全家桶 / gobuster / gitleaks / chisel / amass / dalfox /
# feroxbuster + pip 组（wafw00f/semgrep/pwntools）+ impacket 源码装双名兜底。
# SecLists 不在构建期克隆（约 2.5GB），首次启动由 entrypoint 后台预装。
COPY docker/install-tools.sh /tmp/install-tools.sh
RUN bash /tmp/install-tools.sh && rm -f /tmp/install-tools.sh
# MCP 服务器（mcp-servers/fofa 等 Python FastAPI MCP，MCP 预设项经 uv --directory 启动）
COPY mcp-servers/ /app/mcp-servers/
# uv：MCP 预设「FOFA 资产测绘」用它拉起 Python stdio server（fofa 预设命令为 uv --directory）
RUN python3 -m pip install --no-cache-dir --quiet uv && uv --version
# 注：catalog 全量项的补齐**不在构建期做**（会把镜像再撑大 1–2GB、构建时间翻倍）。
# 改为容器首次启动时后台预装（见 docker/docker-entrypoint.sh）：主服务不被阻塞，
# 安装日志在 data/tools-preinstall.log，「宿主环境」页实时反映进度。
# 已装的会跳过（幂等）；要禁用后台预装：environment: ZRECO_PREINSTALL_TOOLS=0。
# entrypoint：先后台拉起 hostd（root 常驻，「宿主环境」页一键装工具），再 exec start.sh
COPY docker/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh
# data/（任务工作区、流量库、证据等）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
