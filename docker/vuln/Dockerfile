FROM python:3.11-slim

LABEL maintainer="vuln-research"
LABEL description="mdserver-web <=0.18.5 认证绕过+RCE 漏洞复现环境"

# 安装系统依赖（不编译 PHP/MySQL/OpenResty）
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        curl wget git \
        locales \
        cron \
        procps \
        net-tools && \
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

# 将当前代码复制进镜像（不依赖网络拉取，直接使用本地 commit）
COPY . /www/server/mdserver-web/

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
