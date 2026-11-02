"""
Batch 7: Sniffnet Webhook Receiver
Passive HTTP server listening for Sniffnet remote notifications.
Receives JSON alerts → writes to state.json → triggers alert.
"""
import json, os, sys, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(SKILL_DIR, ".gatekeeper.state")

# R2（2026-09-22）：state 序列化单一事实源 —— 勿再内联 json.dump 直写 state。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_json_utils import dump_state, state_lock, submit_state_write  # noqa: E402


def _ingest_alert(alert: dict) -> None:
    """把一条遥测告警并入 state（**在单写者队列里执行**，内部仍持 state_lock 跨进程互斥）。

    A2（2026-10-28）：原实现由 HTTP 请求线程**同步**抢锁读-改-写 ⟹ 多请求并发时互相排队，
    且每个请求的响应时间被磁盘写绑住。改为投递到 gk_json_utils 的单写者队列：HTTP 线程立即
    返回，落盘串行、单写者；进程退出时 atexit 自动 flush（未落盘的数量可在
    `flush_state_writes()` 观测，失败会被记为错误而不是静默丢）。
    """
    if not os.path.exists(STATE_FILE):
        return
    with state_lock(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            s = json.load(f)
        gd = s.setdefault("gate_data", {})
        alerts = gd.setdefault("_sniffnet_alerts", [])
        alerts.append(alert)
        # Cap at 50
        if len(alerts) > 50:
            gd["_sniffnet_alerts"] = alerts[-50:]
        if not dump_state(STATE_FILE, s):
            raise RuntimeError("state 落盘失败: %s" % STATE_FILE)


class SniffnetHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body) if body else {}
            alert = {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "source": "sniffnet",
                "type": data.get("info", "unknown"),
                "data": data
            }
            # Write to state —— 异步单写者（见 _ingest_alert 的 A2 说明）
            submit_state_write(STATE_FILE, lambda a=alert: _ingest_alert(a))
            # Log
            log_dir = os.path.join(SKILL_DIR, "scripts")
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "sniffnet.log"), "a") as f:
                f.write(json.dumps(alert) + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": False, "error": str(e)}).encode())
    def log_message(self, format, *args):
        pass  # Suppress default logging

def run_server(port=8765):
    server = HTTPServer(("127.0.0.1", port), SniffnetHandler)
    print(json.dumps({"ok": True, "message": f"Sniffnet webhook listening on 127.0.0.1:{port}"}))
    server.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    run_server(port)
