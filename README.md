# AI＋资产预警工作台

分行内网安全告警研判的可运行原型。工作台汇集告警、资产和分行知识。收到态势感知或 IDS 告警后，按资产地址匹配台账，按风险等级和资产权重计分。达到阈值的记录进入研判，保存分析和知识引用，并按匹配到的责任人发送通知。

## 本地运行

需要 Python 3.10 或更新版本，无第三方运行依赖。

```bash
python app.py
```

打开 http://127.0.0.1:8000。默认使用虚构数据和模拟研判、通知，可在页面录入知识、登记资产、接入告警、筛选记录并查看结果。演示数据库位于 `var/demo.sqlite3`。

- 评分是风险等级基础分（低危 20、中危 45、高危 70、严重 90）加资产权重（0–20），总分上限 100。默认研判阈值 70，可用 `HX_THRESHOLD` 调整。
- 知识条目按关键词命中数排序，最多引入三条。支持历史告警、运维手册、应急预案和安全手册。
- 相同编号和内容的重复请求返回当前记录。失败或待分派的记录可在详情页重试，通知重试沿用已保存的研判结果。
- 缺少责任人的告警可先登记资产，再在详情页重试分派。
- 每条告警按接入时的评分决定是否研判。低于阈值的记录留档。

### 告警接入示例

```bash
curl -sS http://127.0.0.1:8000/api/alerts \
  -H 'Content-Type: application/json' \
  -d '{"id":"DEMO-001","title":"连续登录失败","source":"态势感知系统","address":"10.20.6.31","severity":"高危","description":"观测到多次失败登录","initial":"疑似异常认证，待核实"}'
```

响应包含告警编号、评分、状态、通知状态和研判结果。处理中或未触发研判时，结果可能为 `null`。健康检查为 `GET /healthz`。

## 行内对接

设置 `HX_MODE=internal` 启用内网 HTTPS 和认证。页面使用账号 `operator` 与 `HX_PASSWORD`，告警设备可用 `Authorization: Bearer <HX_INGEST_TOKEN>` 调用告警接入接口。正式环境默认使用单独的 `var/console.sqlite3`。

| 变量 | 用途 |
| --- | --- |
| `HX_HOST`、`HX_PORT` | 监听地址和端口，默认 127.0.0.1 和 8000 |
| `HX_DB` | SQLite 数据库文件路径 |
| `HX_PASSWORD`、`HX_INGEST_TOKEN` | 控制台密码和设备接入令牌 |
| `HX_TLS_CERT`、`HX_TLS_KEY` | 服务器证书链和私钥文件 |
| `HX_MODEL_URL`、`HX_MODEL_TOKEN` | 中间业务云的研判接口地址及可选 Bearer 令牌 |
| `HX_NOTIFY_URL`、`HX_NOTIFY_TOKEN` | 企业微信通知适配接口地址及可选 Bearer 令牌 |
| `HX_CA_FILE` | 可选，用于校验行内服务证书的 CA 文件 |

研判适配器接收 `{alert, references}`，返回 `{summary, recommendation}`。由中间业务云负责转发至祝融平台等实际模型服务。通知适配器接收 `{alert_id, recipient, title, score, summary, recommendation}`，负责将责任人标识映射至企业微信成员，并在受理后返回 `{"accepted":true}`。两种请求均以告警编号作为 `Idempotency-Key`，下游应支持重试去重。HTTPS 支持 TLS 1.2 及以上，入站 TLS 1.2 使用 ECDHE 与 AEAD 套件，出站校验证书与主机名。

接口格式是原型定义，实际字段映射、凭据和通知回执语义需按行内规范联调。当前服务按单实例运行；7×24 可用性需通过正式部署、监控、备份、故障恢复和验收验证。

## 验证

```bash
python -m unittest discover -s tests -v
```
