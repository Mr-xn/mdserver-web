#!/bin/bash
# ============================================================
# clean.sh - 完全清理漏洞复现环境
#            删除：容器 + 镜像 + 网络 + 挂载卷
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

IMAGE_NAME="mdserver-web-vuln:0.18.4"
CONTAINER_NAME="mdserver-web-vuln"
NETWORK_NAME="mdserver_vuln_net"
VOLUMES="mdserver_vuln_data mdserver_vuln_logs mdserver_vuln_cron"

echo "================================================================"
echo "  mdserver-web 0.18.4 漏洞复现环境 - 完全清理"
echo "================================================================"
echo "⚠️  此操作将删除容器、镜像、网络及所有挂载卷，数据不可恢复！"
read -r -p "确认继续? [y/N] " confirm
if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
    echo "已取消。"
    exit 0
fi

echo ""
echo "[1/5] 停止并删除容器..."
docker compose -f "${COMPOSE_FILE}" down --remove-orphans 2>/dev/null || true
docker rm -f "${CONTAINER_NAME}" 2>/dev/null && echo "  → 容器 ${CONTAINER_NAME} 已删除" || echo "  → 容器不存在，跳过"

echo "[2/5] 删除漏洞镜像..."
docker rmi -f "${IMAGE_NAME}" 2>/dev/null && echo "  → 镜像 ${IMAGE_NAME} 已删除" || echo "  → 镜像不存在，跳过"

echo "[3/5] 删除挂载卷..."
for vol in ${VOLUMES}; do
    docker volume rm "${vol}" 2>/dev/null && echo "  → 卷 ${vol} 已删除" || echo "  → 卷 ${vol} 不存在，跳过"
done

echo "[4/5] 删除网络..."
docker network rm "${NETWORK_NAME}" 2>/dev/null && echo "  → 网络 ${NETWORK_NAME} 已删除" || echo "  → 网络不存在，跳过"

echo "[5/5] 清理构建缓存（可选）..."
read -r -p "是否同时清理 Docker 构建缓存? [y/N] " clean_cache
if [[ "${clean_cache}" == "y" || "${clean_cache}" == "Y" ]]; then
    docker builder prune -f
    echo "  → 构建缓存已清理"
fi

echo ""
echo "  ✅  清理完成。如需重新搭建，请执行 start.sh"
echo "================================================================"
