#!/bin/bash
# ============================================================
# start.sh - 启动 mdserver-web 漏洞复现环境
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

echo "================================================================"
echo "  mdserver-web 0.18.4 漏洞复现环境 - 启动"
echo "================================================================"

# 切换到仓库根目录（构建上下文）
cd "${SCRIPT_DIR}/../../"

echo "[1/3] 构建漏洞镜像（首次约需 2-5 分钟，后续秒级）..."
docker compose -f "${COMPOSE_FILE}" build

echo "[2/3] 启动容器..."
docker compose -f "${COMPOSE_FILE}" up -d

echo "[3/3] 等待服务就绪..."
sleep 5

# 获取面板初始密码
PASS=$(docker exec mdserver-web-vuln cat /www/server/mdserver-web/data/default.pl 2>/dev/null || echo "（密码文件尚未生成，请稍候再试）")
USER=$(docker exec mdserver-web-vuln \
    python3 -c "
import sys; sys.path.insert(0,'/www/server/mdserver-web/web')
import os; os.chdir('/www/server/mdserver-web/web')
import thisdb; u=thisdb.getUserByRoot(); print(u['name'] if u else 'N/A')
" 2>/dev/null || echo "N/A")
SAFE_PATH=$(docker exec mdserver-web-vuln \
    python3 -c "
import sys; sys.path.insert(0,'/www/server/mdserver-web/web')
import os; os.chdir('/www/server/mdserver-web/web')
import thisdb; print(thisdb.getOption('admin_path') or '')
" 2>/dev/null || echo "")

echo ""
echo "================================================================"
echo "  ✅  环境已就绪"
echo "================================================================"
echo "  面板地址  : http://127.0.0.1:7200/${SAFE_PATH}"
echo "  用户名    : ${USER}"
echo "  密码      : ${PASS}"
echo ""

# 验证容器运行的是漏洞代码（crontab 路由未全保护）
# 注：APP_VERSION 来自最新版 version.py，仍显示当前版本号；
# 漏洞状态应通过 @panel_login_required 数量来判断。
PROTECTED_COUNT=$(docker exec mdserver-web-vuln grep -c "@panel_login_required" \
  /www/server/mdserver-web/web/admin/crontab/__init__.py 2>/dev/null || echo "?")
echo "  📋 crontab 路由 @panel_login_required 数量: ${PROTECTED_COUNT}"
if [ "${PROTECTED_COUNT}" = "3" ]; then
  echo "  ✅ 漏洞代码确认：crontab 仅 3 处有认证（8 个路由无保护：logs/del/del_logs/set_cron_status/get_data_list/get_crond_find/modify_crond/start_task）"
elif [ "${PROTECTED_COUNT}" = "11" ]; then
  echo "  ⚠️  检测到修复版本代码（11 处认证），未授权路由漏洞复现将失败，请重新构建镜像"
else
  echo "  ⚠️  认证装饰器数量异常（${PROTECTED_COUNT}），请检查镜像内容"
fi
echo ""
echo "  ℹ️  如安全路径为空，直接访问 http://127.0.0.1:7200/login"
echo "  ℹ️  容器名  : mdserver-web-vuln"
echo "  ℹ️  查看日志: docker logs -f mdserver-web-vuln"
echo "================================================================"
