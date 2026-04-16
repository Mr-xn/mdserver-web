#!/bin/bash
# ============================================================
# start.sh - 启动 mdserver-web 漏洞复现环境
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

echo "================================================================"
echo "  mdserver-web <=0.18.4 漏洞复现环境 - 启动"
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

# 验证容器运行的是漏洞版本（0.18.4）
VERSION=$(docker exec mdserver-web-vuln python3 -c \
  "import sys; sys.path.insert(0,'/www/server/mdserver-web/web'); from version import APP_VERSION; print(APP_VERSION)" \
  2>/dev/null || echo "unknown")
PROTECTED_COUNT=$(docker exec mdserver-web-vuln grep -c "@panel_login_required" \
  /www/server/mdserver-web/web/admin/crontab/__init__.py 2>/dev/null || echo "?")
echo "  📋 版本验证: ${VERSION}"
if [ "${VERSION}" = "0.18.4" ]; then
  echo "  ✅ 漏洞版本确认：运行的是 0.18.4（存在漏洞）"
else
  echo "  ⚠️  版本异常：期望 0.18.4，实际 ${VERSION}，漏洞复现可能失败"
fi
echo "  📋 crontab 路由 @panel_login_required 数量: ${PROTECTED_COUNT}（漏洞版本应为 4，修复版本为 12）"
echo ""
echo "  ℹ️  如安全路径为空，直接访问 http://127.0.0.1:7200/login"
echo "  ℹ️  容器名  : mdserver-web-vuln"
echo "  ℹ️  查看日志: docker logs -f mdserver-web-vuln"
echo "================================================================"
