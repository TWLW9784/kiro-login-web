# Kiro Login Web

独立批量登录站点：批量填写 AWS IAM Identity Center / Microsoft 365 组织账号，后端用 Playwright 无头登录 Kiro，自动检查可用性、按需开通 API Key，导出扁平 JSON 数组或 API Key 清单。

## 功能

- **两种登录方式**
  - AWS IAM Identity Center（IDC）设备码流程
  - Microsoft 365 / Entra ID 组织 SSO（OAuth auth-code + PKCE + 本地回环回调）
- **MFA 自动处理**：自动绑定 TOTP、复用已有密钥；已绑定 MFA 但无预设密钥时秒退并给出准确提示
- **凭据导出**：总 JSON、按数量拆分的 ZIP、API Key 清单、MFA 密钥、账号密码
- **API Key 开通**：可选同步开通或仅开通 API Key
- **密码模式**：固定新密码 / 随机新密码；支持全角符号转半角
- **客户空间隔离**：按客户密码隔离任务、日志、下载文件
- **代理池**：粘贴一批代理轮流分配给账号；可按客户持久化保存
- **防风控换 IP**：撞 captcha / 代理报错时自动换出口 IP 重试
  - 本地部署配了 mihomo → 切节点换 IP
  - 无 mihomo 但有代理池 → 在池内轮换到不同代理
- **排队调度**：超并发上限的任务自动排队，有容量时 FIFO 启动
- **自定义数据保留时长**：导出文件/日志默认保留 24 小时，可按任务在 5 分钟 ~ 7 天间自定义，过期自动删除

## 安装

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

## 启动

```bash
python app.py --host 0.0.0.0 --port 7888
```

也可下载 [Releases](https://github.com/TWLW9784/kiro-login-web/releases) 里对应平台的单文件可执行程序，免装 Python 直接运行。

## 客户密码隔离

网站入口会强制要求输入客户专属密码。不同密码对应不同客户空间，任务、日志、下载文件都按客户隔离。

- 密码已存在：进入对应客户空间。
- 密码第一次使用：自动创建新客户空间，可填写客户名称。
- 新自助客户只存 `passwordHash`（PBKDF2-SHA256）与登录查找索引 `lookupHash`，不保存明文密码。

> **登录性能**：客户密码存有确定性查找索引 `lookupHash`（HMAC-SHA256，密钥派生自服务端 Flask secret），登录时先 O(1) 定位候选再做 PBKDF2 校验，客户数再多登录也是毫秒级。老数据首次登录时自动补写索引（自愈迁移），无需手动处理。

也可以预先编辑 `customers.json` 固定客户：

```json
{
  "customer-a": { "name": "客户A", "password": "明文（首次登录后会自动转 hash）" },
  "customer-b": { "name": "客户B", "passwordHash": "pbkdf2_sha256$..." }
}
```

## 账号格式

每行一个：

```text
email:password
email|password|proxy
email,password,proxy
```

- AWS IDC 模式需填写 Start URL（也可从账号文本中自动提取）。
- M365 组织 SSO 模式无需 Start URL（门户自动做 home realm discovery）。

## 导出字段

扁平 JSON，字段随登录方式略有不同：

- 通用：`email / idp / profileArn / machineId / priority / status / accessToken / refreshToken / clientId / region / expiresAt`
- IDC：额外 `clientSecret / startUrl`
- M365/external_idp：`authMethod=external_idp`、额外 `issuer_url / token_endpoint / scopes`，**无 clientSecret**（public client + PKCE）

## 代理与防风控

- 在「代理池」文本框粘贴代理（每行一个，支持 `http:// https:// socks5://` 及裸 `host:port`），会轮流分配给未单独指定代理的账号。
- 勾选「保存代理池」可持久化到客户配置，下次自动回填。
- 机房代理下并发越高越容易撞 captcha，默认并行数为 2；挂住宅/移动代理可适当调高。
- 撞 captcha / 代理连接失败时自动换 IP 重试（详见上方功能列表）。

## 数据保留

导出 JSON / API Key / MFA / 账号密码 / 日志默认保留 **24 小时**，可在「更多配置 → 账号数据保留时长」按任务自定义（5 分钟 ~ 7 天）。过期自动删除、下载链接失效。含明文密码 / MFA 密钥，请及时下载。

## 环境变量（可选）

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `KIRO_DEFAULT_PROXY` | 服务端兜底默认代理 | 无 |
| `KIRO_MIHOMO_CONTROLLER` | mihomo 外部控制器地址（换 IP 用） | `http://127.0.0.1:9090` |
| `KIRO_MIHOMO_SECRET` | mihomo 控制器密钥 | 无 |
| `KIRO_MIHOMO_GROUP` | mihomo 代理组名 | `KiroLogin` |
| `KIRO_MIHOMO_PROBE_PROXY` | 探测真实出口 IP 用的代理 | `http://127.0.0.1:7895` |

> mihomo 相关变量仅本地部署换 IP 时需要；开源用户用代理池即可获得同等的换 IP 能力。
