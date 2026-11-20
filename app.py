"""Branch security alert triage console."""
import base64
import hmac
import json
import os
import re
import sqlite3
import ssl
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
LEVELS = {"低危": 20, "中危": 45, "高危": 70, "严重": 90}
KINDS = ("历史告警", "运维手册", "应急预案", "安全手册")
SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  address TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, criticality INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS knowledge (
  id INTEGER PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL, keywords TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, source TEXT NOT NULL, address TEXT NOT NULL,
  severity TEXT NOT NULL, description TEXT NOT NULL, initial TEXT NOT NULL,
  asset TEXT, owner TEXT, score INTEGER NOT NULL, state TEXT NOT NULL, result TEXT,
  notification TEXT NOT NULL DEFAULT '未发送', error TEXT, created TEXT NOT NULL
);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fields(data, names, limit=2000):
    if not isinstance(data, dict):
        raise ValueError("请求必须为 JSON 对象")
    result = []
    for name in names:
        value = data.get(name)
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
            raise ValueError(f"{name} 必须填写，长度不得超过 {limit} 个字符")
        result.append(value.strip())
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_https(url, payload, token=None, alert_id=None):
    endpoint = urlsplit(url)
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None:
        raise ValueError("对接端点必须使用 HTTPS")
    context = ssl.create_default_context(cafile=os.getenv("HX_CA_FILE"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if alert_id:
        headers["Idempotency-Key"] = alert_id
    opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
    request = Request(url, data=json.dumps(payload, ensure_ascii=False).encode(), headers=headers)
    with opener.open(request, timeout=15) as response:
        content = response.read(262145)
    if len(content) > 262144:
        raise ValueError("对接响应过大")
    return json.loads(content)


class Console:
    def __init__(self, path, demo=True):
        self.path = path
        self.demo = demo
        self.threshold = int(os.getenv("HX_THRESHOLD", "70"))
        if not 1 <= self.threshold <= 100:
            raise ValueError("HX_THRESHOLD 必须为 1–100")
        with closing(self.connect()) as db, db:
            db.executescript(SCHEMA)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def list(self, table):
        queries = {
            "alerts": "SELECT * FROM alerts ORDER BY created DESC, rowid DESC",
            "assets": "SELECT * FROM assets ORDER BY name",
            "knowledge": "SELECT * FROM knowledge ORDER BY id DESC",
        }
        with closing(self.connect()) as db:
            rows = [dict(row) for row in db.execute(queries[table])]
        if table == "alerts":
            for row in rows:
                row["result"] = json.loads(row["result"]) if row["result"] else None
        return rows

    def add_asset(self, data):
        address, name, owner = fields(data, ("address", "name", "owner"), 100)
        criticality = data.get("criticality")
        if type(criticality) is not int or not 0 <= criticality <= 20:
            raise ValueError("资产权重必须是 0–20 的整数")
        with closing(self.connect()) as db, db:
            db.execute("""INSERT INTO assets VALUES (?, ?, ?, ?) ON CONFLICT(address)
                DO UPDATE SET name=excluded.name, owner=excluded.owner, criticality=excluded.criticality
                """, (address, name, owner, criticality))

    def add_knowledge(self, data):
        title, kind, keywords, body = fields(data, ("title", "kind", "keywords", "body"), 5000)
        if kind not in KINDS:
            raise ValueError("知识类型无效")
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO knowledge(title,kind,keywords,body) VALUES (?,?,?,?)",
                       (title, kind, keywords, body))

    def ingest(self, data):
        alert_id, title, source, address, severity = fields(
            data, ("id", "title", "source", "address", "severity"), 120)
        description, initial = fields(data, ("description", "initial"))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", alert_id) or severity not in LEVELS:
            raise ValueError("告警编号或风险等级无效")
        with closing(self.connect()) as db, db:
            asset = db.execute("SELECT * FROM assets WHERE address=?", (address,)).fetchone()
            score = min(100, LEVELS[severity] + (asset["criticality"] if asset else 0))
            state = "待研判" if score >= self.threshold else "低于阈值"
            inserted = db.execute("""INSERT INTO alerts
                (id,title,source,address,severity,description,initial,asset,owner,score,state,created)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
                (alert_id, title, source, address, severity, description, initial,
                 asset["name"] if asset else None, asset["owner"] if asset else None, score, state, now())
            ).rowcount
            if not inserted:
                existing = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
                names = ("title", "source", "address", "severity", "description", "initial")
                if tuple(existing[name] for name in names) != (title, source, address, severity, description, initial):
                    raise ValueError("告警编号已存在，且内容不同")
        if inserted and state == "待研判":
            self.process(alert_id)
        with closing(self.connect()) as db:
            row = db.execute("SELECT id, score, state, notification, result FROM alerts WHERE id=?", (alert_id,)).fetchone()
        response = dict(row)
        response["result"] = json.loads(response["result"]) if response["result"] else None
        return response

    def references(self, alert):
        text = " ".join(alert[key] for key in ("title", "description", "initial")).casefold()
        matches = []
        for entry in self.list("knowledge"):
            keywords = set(re.split(r"[、，,\s]+", entry["keywords"].casefold()))
            hits = sum(bool(word) and word in text for word in keywords)
            if hits:
                matches.append((hits, entry))
        return [entry for _, entry in sorted(matches, key=lambda pair: -pair[0])[:3]]

    def analyze(self, alert):
        references = self.references(alert)
        if self.demo:
            result = {
                "summary": f"风险评分 {alert['score']}。初步结论为「{alert['initial']}」，需由值班人员复核。",
                "recommendation": "核对告警时间、来源和资产日志，参照关联知识确认影响范围，再按值班流程处置。",
            }
        else:
            result = post_https(os.environ["HX_MODEL_URL"], {
                "alert": {key: alert[key] for key in (
                    "id", "title", "source", "address", "severity", "description", "initial", "score")},
                "references": [{key: ref[key] for key in ("id", "title", "kind", "body")} for ref in references],
            }, os.getenv("HX_MODEL_TOKEN"), alert["id"])
            fields(result, ("summary", "recommendation"), 4000)
        return {
            "summary": result["summary"], "recommendation": result["recommendation"],
            "references": [{key: ref[key] for key in ("id", "title", "kind")} for ref in references],
            "mode": "本地模拟" if self.demo else "总行模型",
        }

    def notify(self, alert, result):
        if not alert["owner"]:
            return "缺少责任人"
        if self.demo:
            return "模拟已发送"
        # The middleware resolves the owner to their enterprise messaging identity.
        receipt = post_https(os.environ["HX_NOTIFY_URL"], {
            "alert_id": alert["id"], "recipient": alert["owner"], "title": alert["title"],
            "score": alert["score"], "summary": result["summary"], "recommendation": result["recommendation"],
        }, os.getenv("HX_NOTIFY_TOKEN"), alert["id"])
        if not isinstance(receipt, dict) or receipt.get("accepted") is not True:
            raise ValueError("通知服务未确认受理")
        return "已受理"

    def process(self, alert_id):
        with closing(self.connect()) as db:
            with db:
                claimed = db.execute("""UPDATE alerts SET state='处理中',error=NULL
                    WHERE id=? AND state IN ('待研判','研判失败','通知失败','待分派')""", (alert_id,)).rowcount
            if not claimed:
                return False
            alert = dict(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            if not alert["owner"]:
                asset = db.execute("SELECT name, owner FROM assets WHERE address=?", (alert["address"],)).fetchone()
                if asset:
                    alert.update(asset=asset["name"], owner=asset["owner"])
                    with db:
                        db.execute("UPDATE alerts SET asset=?,owner=? WHERE id=?",
                                   (alert["asset"], alert["owner"], alert_id))
            result = alert["result"]
            try:
                if not result:
                    result = json.dumps(self.analyze(alert), ensure_ascii=False)
                    with db:
                        db.execute("UPDATE alerts SET result=? WHERE id=?", (result, alert_id))
                notification = self.notify(alert, json.loads(result))
                state = "待分派" if notification == "缺少责任人" else "已完成"
                error = None
            except (OSError, ValueError, KeyError):
                state = "通知失败" if result else "研判失败"
                notification = "待重试" if result else "未发送"
                error = "对接请求失败或返回格式不符，请检查服务配置后重试。"
            with db:
                db.execute("UPDATE alerts SET state=?,notification=?,error=? WHERE id=?",
                           (state, notification, error, alert_id))
        return True

    def seed(self):
        with closing(self.connect()) as db:
            if db.execute("SELECT 1 FROM alerts LIMIT 1").fetchone():
                return
        for address, name, owner, criticality in [
            ("10.20.4.18", "核心业务网关", "张宁", 20),
            ("10.20.6.31", "身份认证服务", "陈晨", 15),
            ("10.20.8.12", "办公应用服务器", "林悦", 10),
            ("10.20.9.24", "内网日志节点", "许嘉", 5),
        ]:
            self.add_asset(dict(address=address, name=name, owner=owner, criticality=criticality))
        for title, kind, keywords, body in [
            ("异常认证告警处置手册", "运维手册", "认证,登录,失败", "比对认证日志并联系资产责任人核实账号来源。"),
            ("异常通信应急预案", "应急预案", "连接,流量,通信", "保存告警证据，复核通信目的及资产近期变更。"),
            ("近期主机异常告警复盘", "历史告警", "主机,进程", "校验主机审计日志与已批准的变更记录。"),
        ]:
            self.add_knowledge(dict(title=title, kind=kind, keywords=keywords, body=body))
        for counter, (title, address, severity, initial) in enumerate([
            ("内网日志节点流量波动", "10.20.9.24", "低危", "采集流量略高于基线"),
            ("办公应用服务器异常连接", "10.20.8.12", "中危", "检测到连接频率升高"),
            ("办公主机进程行为异常", "10.20.8.12", "高危", "发现未登记的进程活动"),
            ("身份认证服务连续登录失败", "10.20.6.31", "高危", "同一账户短时间出现多次认证失败"),
            ("核心业务网关异常通信", "10.20.4.18", "严重", "检测到偏离基线的出站连接"),
        ], 101):
            self.ingest(dict(id=f"ALT-{counter}", title=title, source="态势感知系统", address=address,
                             severity=severity, description=title, initial=initial))


class Handler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type, authenticate=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        if authenticate:
            self.send_header("WWW-Authenticate", 'Basic realm="Alert Console", charset="UTF-8"')
        self.end_headers()
        self.wfile.write(body)

    def json(self, status, data):
        self.send_body(status, json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def authorized(self, ingest=False):
        if self.server.console.demo:
            return True
        supplied = self.headers.get("Authorization", "").encode()
        if ingest and hmac.compare_digest(supplied, ("Bearer " + os.environ["HX_INGEST_TOKEN"]).encode()):
            return True
        expected = "Basic " + base64.b64encode(("operator:" + os.environ["HX_PASSWORD"]).encode()).decode()
        if hmac.compare_digest(supplied, expected.encode()):
            return True
        self.send_body(401, b"Authentication required", "text/plain", authenticate=not ingest)
        return False

    def do_GET(self):
        if self.path == "/healthz":
            try:
                with closing(self.server.console.connect()) as db:
                    db.execute("SELECT id FROM alerts LIMIT 1").fetchone()
            except sqlite3.Error:
                return self.json(503, {"status": "unavailable"})
            return self.json(200, {"status": "ok"})
        if not self.authorized():
            return
        console = self.server.console
        if self.path == "/api/overview":
            return self.json(200, {table: console.list(table) for table in ("alerts", "assets", "knowledge")}
                             | {"demo": console.demo, "threshold": console.threshold})
        assets = {
            "/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
            "/style.css": ("style.css", "text/css"),
        }
        if self.path in assets:
            filename, mime = assets[self.path]
            return self.send_body(200, (ROOT / "static" / filename).read_bytes(), mime + "; charset=utf-8")
        self.json(404, {"error": "页面不存在"})

    def do_POST(self):
        if not self.authorized(ingest=self.path == "/api/alerts"):
            return
        if self.headers.get_content_type() != "application/json":
            return self.json(415, {"error": "请求类型必须是 application/json"})
        console = self.server.console
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 32768:
                return self.json(413, {"error": "请求体长度无效"})
            data = json.loads(self.rfile.read(length))
            if self.path == "/api/alerts":
                return self.json(200, console.ingest(data))
            if self.path == "/api/assets":
                console.add_asset(data)
            elif self.path == "/api/knowledge":
                console.add_knowledge(data)
            elif self.path == "/api/retry":
                (alert_id,) = fields(data, ("id",), 120)
                if not console.process(alert_id):
                    return self.json(409, {"error": "告警当前不可重试"})
            else:
                return self.json(404, {"error": "接口不存在"})
            self.json(200, {"ok": True})
        except ValueError as error:
            self.json(400, {"error": str(error) if type(error) is ValueError else "JSON 格式无效"})


def main():
    mode = os.getenv("HX_MODE", "demo")
    if mode not in {"demo", "internal"}:
        raise SystemExit("HX_MODE 必须为 demo 或 internal")
    demo = mode == "demo"
    if not demo:
        required = ("HX_PASSWORD", "HX_INGEST_TOKEN", "HX_MODEL_URL", "HX_NOTIFY_URL", "HX_TLS_CERT", "HX_TLS_KEY")
        if missing := [key for key in required if not os.getenv(key)]:
            raise SystemExit("缺少配置：" + ", ".join(missing))
    default_db = "demo.sqlite3" if demo else "console.sqlite3"
    path = Path(os.getenv("HX_DB", ROOT / "var" / default_db))
    path.parent.mkdir(parents=True, exist_ok=True)
    console = Console(path, demo=demo)
    # A single service instance owns the database. Resume interrupted work on restart.
    with closing(console.connect()) as db, db:
        db.execute("""UPDATE alerts SET state=CASE WHEN result IS NULL THEN '研判失败'
            ELSE '通知失败' END,error='上次处理被中断，请重试。' WHERE state='处理中'""")
    if demo:
        console.seed()
    server = ThreadingHTTPServer((os.getenv("HX_HOST", "127.0.0.1"), int(os.getenv("HX_PORT", "8000"))), Handler)
    server.console = console
    if not demo:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        context.load_cert_chain(os.environ["HX_TLS_CERT"], os.environ["HX_TLS_KEY"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"{'http' if demo else 'https'}://{server.server_name}:{server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
