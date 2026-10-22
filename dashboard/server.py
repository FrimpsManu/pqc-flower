"""Local dashboard for the prototype: runs the real system (scripts/run_local.sh) and shows it live.

Usage: .venv/bin/python dashboard/server.py   then open http://127.0.0.1:8765
One job runs at a time; the page polls /api/job for new output lines.
"""

import json
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
PORT = int(os.environ.get("DASHBOARD_PORT", "8765"))
ANSI = re.compile(r"\x1b\[[0-9;]*m")
MODES = {"insecure", "classical", "pqc"}

job = {"id": 0, "kind": None, "lines": [], "running": False, "exit": None, "proc": None}
lock = threading.Lock()


def _run(cmd: list[str], env: dict) -> None:
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    job["proc"] = proc
    for line in proc.stdout:
        job["lines"].append(ANSI.sub("", line.rstrip("\n")))
    job["exit"] = proc.wait()
    job["running"] = False


def start(spec: dict) -> dict:
    kind = spec.get("kind")
    mode = spec.get("mode", "classical")
    if mode not in MODES:
        return {"error": f"unknown mode {mode}"}
    if kind == "train":
        rounds = max(1, min(int(spec.get("rounds", 8)), 30))
        signed = "true" if spec.get("signed") else "false"
        attack = "0" if spec.get("attack") else "-1"
        cmd = [str(ROOT / "scripts/run_local.sh"), mode, "3", str(rounds),
               f"sign-updates={signed} attack-farm={attack}"]
    elif kind == "attack2":
        if mode == "insecure":
            return {"error": "Attack 2 needs farm login (classical or pqc)"}
        cmd = [str(HERE / "attack2_once.sh"), mode]
    else:
        return {"error": f"unknown job kind {kind}"}
    with lock:
        if job["running"]:
            return {"error": "another run is in progress"}
        job.update(id=job["id"] + 1, kind=kind, spec=spec, lines=[], running=True, exit=None)
        threading.Thread(target=_run, args=(cmd, {**os.environ, "PYTHONUNBUFFERED": "1"}), daemon=True).start()
        return {"id": job["id"]}


def stop() -> None:
    proc = job.get("proc")
    if job["running"] and proc:
        proc.terminate()
    subprocess.run([str(ROOT / "scripts/stop_all.sh"), "--quiet"])


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(json.dumps(obj).encode(), "application/json", code)

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        if path == "/":
            self._send((HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/job":
            since = int(dict(p.split("=") for p in query.split("&") if "=" in p).get("since", 0))
            self._json({"id": job["id"], "kind": job["kind"], "running": job["running"], "exit": job["exit"],
                        "lines": job["lines"][since:], "total": len(job["lines"])})
        elif path == "/api/costs":
            files = sorted((ROOT / "results").glob("pqc_costs_*.json"))
            self._json(json.loads(files[-1].read_text()) if files else {})
        else:
            self._send(b"not found", "text/plain", 404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        spec = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/run":
            result = start(spec)
            self._json(result, 409 if "error" in result else 200)
        elif self.path == "/api/stop":
            stop()
            self._json({"stopped": True})
        else:
            self._send(b"not found", "text/plain", 404)

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    print(f"Dashboard: http://127.0.0.1:{PORT}  (Ctrl+C to quit)")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        stop()
