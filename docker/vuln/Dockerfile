FROM python:3.11-slim

LABEL maintainer="vuln-research"
LABEL description="mdserver-web 0.18.4 认证绕过+RCE 漏洞复现环境"

# 安装系统依赖（不编译 PHP/MySQL/OpenResty）
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        curl wget \
        locales \
        cron \
        procps \
        net-tools \
        gcc python3-dev && \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# 创建面板目录结构
RUN mkdir -p /www/server/mdserver-web/data && \
    mkdir -p /www/server/mdserver-web/logs && \
    mkdir -p /www/server/mdserver-web/tmp && \
    mkdir -p /www/server/cron && \
    mkdir -p /www/wwwroot && \
    mkdir -p /www/backup

# 将当前代码（最新版）复制进镜像
COPY . /www/server/mdserver-web/

# 用 tag 0.18.4 的漏洞版本覆盖已修复的两个文件（共 9 个路由），
# 使容器同时具备：
#   - 旧版未授权路由漏洞（crontab 8 个 + get_site_doc 1 个）
#   - 全版本 API Key 认证绕过漏洞（user_login_check.py 未改动，最新版仍存在）
# 无需在镜像内使用 git，避免构建上下文不含 .git 时的 fatal 错误。
COPY docker/vuln/vuln_web/admin/crontab/__init__.py \
     /www/server/mdserver-web/web/admin/crontab/__init__.py
COPY docker/vuln/vuln_web/admin/site/site_default.py \
     /www/server/mdserver-web/web/admin/site/site_default.py

# 安装 Python 依赖（过滤掉版本无效的 zmq==0.0.0）
RUN pip install --no-cache-dir --upgrade pip && \
    grep -v '^zmq==0.0.0' /www/server/mdserver-web/requirements.txt > /tmp/requirements-fixed.txt && \
    pip install --no-cache-dir -r /tmp/requirements-fixed.txt

# 设置面板端口（固定 7200，避免随机端口）
RUN echo "7200" > /www/server/mdserver-web/data/port.pl

WORKDIR /www/server/mdserver-web/web

# 复制启动脚本
COPY docker/vuln/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 7200

CMD ["/entrypoint.sh"]
