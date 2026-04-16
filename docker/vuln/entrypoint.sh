#!/bin/bash
set -e

PANEL_DIR=/www/server/mdserver-web
DATA_DIR=${PANEL_DIR}/data
LOG_DIR=${PANEL_DIR}/logs

# 确保目录存在
mkdir -p "${DATA_DIR}" "${LOG_DIR}" /www/server/cron

# 确保端口文件存在
if [ ! -f "${DATA_DIR}/port.pl" ]; then
    echo "7200" > "${DATA_DIR}/port.pl"
fi

echo "[*] 面板数据目录: ${DATA_DIR}"
echo "[*] 面板日志目录: ${LOG_DIR}"
echo "[*] 面板端口: $(cat ${DATA_DIR}/port.pl)"
echo "[*] 启动 mdserver-web 漏洞复现环境 ..."

cd ${PANEL_DIR}/web

# 以前台模式运行 gunicorn（Docker 不能 daemon）
exec gunicorn \
    -w 2 \
    -b 0.0.0.0:7200 \
    --worker-class gthread \
    --threads 4 \
    --timeout 600 \
    --keep-alive 60 \
    --access-logfile "${LOG_DIR}/panel.log" \
    --error-logfile "${LOG_DIR}/panel_error.log" \
    --log-level info \
    app:app
