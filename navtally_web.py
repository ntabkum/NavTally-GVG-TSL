#!/usr/bin/env python3
"""
navtally_web.py - tiny web GUI launcher for NavTally-GVG.py (standard library only).

    python navtally_web.py                 # then open http://127.0.0.1:8080
    python navtally_web.py --web-port 9000 --web-host 0.0.0.0   # reachable from other PCs (no auth!)

The page (navtally_gui.html, same folder) lets you set the options, Start / Stop the tally
script as a subprocess, and watch its log live. Nothing is run through a shell; every field is
validated and turned into a plain argument list.
"""
import argparse, collections, ipaddress, json, os, re, socket, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
BUSES = ["ME1", "ME2", "ME3", "ME4", "PGM"]
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
OUTLIST_RE = re.compile(r"^[0-9,\- ]*$")
OUTPUTS_RE = re.compile(r"^[A-Za-z0-9, ]+$")


class Runner:
    def __init__(self, script):
        self.script = script
        self.proc = None
        self.cmd = []
        self.lines = collections.deque(maxlen=3000)
        self.seq = 0
        self.lock = threading.Lock()

    def _add(self, text):
        with self.lock:
            self.seq += 1
            self.lines.append((self.seq, text))

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, cmd):
        if self.running():
            raise RuntimeError("already running")
        self.cmd = cmd
        self._add("=== START: " + " ".join(cmd[3:]))
        self.proc = subprocess.Popen(cmd, cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1, errors="replace")
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()

    def _pump(self, proc):
        for line in proc.stdout:
            self._add(line.rstrip())
        proc.wait()
        self._add(f"=== STOPPED (exit code {proc.returncode})")

    def stop(self):
        p = self.proc
        if not p or p.poll() is not None:
            return False
        p.terminate()
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()
        return True

    def log_since(self, since):
        with self.lock:
            return [t for s, t in self.lines if s > since], self.seq


def _int(d, key, lo, hi, default=None):
    v = d.get(key, default)
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a whole number")
    if not lo <= v <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return v


def _host(d, key, required=True):
    v = str(d.get(key, "")).strip()
    if not v and not required:
        return ""
    if not HOST_RE.match(v):
        raise ValueError(f"{key} is not a valid IP address / host name")
    return v


def _buses(d, key):
    v = d.get(key, [])
    if not isinstance(v, list) or any(b not in BUSES for b in v):
        raise ValueError(f"{key}: unknown bus")
    return ",".join(v) if v else "none"


def _suites(d, key):
    v = d.get(key, [])
    if not isinstance(v, list) or any(s not in (1, 2, 3, 4) for s in v):
        raise ValueError(f"{key}: suites must be 1-4")
    return ",".join(str(s) for s in sorted(set(v))) if v else "none"


def _bind(d, key):
    v = str(d.get(key, "")).strip()
    if not v:
        return ""
    try:
        ip = ipaddress.IPv4Address(v)
    except ValueError:
        raise ValueError(f"{key} must be a local IPv4 address (or empty for automatic)")
    return str(ip)


def list_interfaces():
    """Local IPv4 addresses as [{'name':..., 'ip':...}], best effort without extra packages."""
    found = {}
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for ad in addrs:
                if ad.family == socket.AF_INET:
                    found[ad.address] = name
    except Exception:
        pass

    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5, errors="replace").stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    if not found:
        for m in re.finditer(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", run(["ip", "-4", "-o", "addr", "show"]), re.M):
            found[m.group(2)] = m.group(1)
    if not found and os.name == "nt":
        adapter = ""
        for line in run(["ipconfig"]).splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                adapter = line.rstrip().rstrip(":").strip()
            elif "IPv4" in line:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    found[m.group(1)] = adapter
    if not found:
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                found[ip] = "host"
        except OSError:
            pass
    found.setdefault("127.0.0.1", "loopback")
    key = lambda ip: tuple(int(x) for x in ip.split("."))
    return [{"name": found[ip], "ip": ip} for ip in sorted(found, key=key)]


def _extra(d):
    v = d.get("udp_extra", [])
    if not isinstance(v, list):
        raise ValueError("udp_extra must be a list")
    items = []
    for x in v:
        host = str(x.get("host", "")).strip() if isinstance(x, dict) else ""
        if not host:
            continue
        if not HOST_RE.match(host):
            raise ValueError(f"additional destination '{host}' is not a valid IP address / host name")
        port = str(x.get("port", "")).strip()
        if port:
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError(f"additional destination {host}: port must be 1-65535")
            host += ":" + port
        start = str(x.get("start", "")).strip()
        if start:
            count = str(x.get("count", "")).strip() or "1"
            if not (start.isdigit() and count.isdigit()) or not 0 <= int(start) <= 65534 or not 1 <= int(count) <= 65535:
                raise ValueError(f"additional destination {host}: start address 0-65534 and count 1-65535")
            host += f"@{int(start)}+{int(count)}"
        items.append(host)
    if len(items) > 9:
        raise ValueError("at most 9 additional destinations (10 hosts in total)")
    return ",".join(items)


def _outs(d, key):
    v = str(d.get(key, "")).strip()
    if not OUTLIST_RE.match(v):
        raise ValueError(f"{key}: use numbers like 1,2,5-8")
    return v


def build_cmd(script, d):
    mock = bool(d.get("mock"))
    ver = str(d.get("tsl_version", "3.1"))
    if ver not in ("3.1", "5"):
        raise ValueError("tsl_version must be 3.1 or 5")
    label = str(d.get("label", "name"))
    if label not in ("name", "oled", "panel", "menu"):
        raise ValueError("label must be name, oled, panel or menu")
    outputs = str(d.get("outputs", "PgmA,PgmB,PgmC,PgmD")).strip()
    if not OUTPUTS_RE.match(outputs):
        raise ValueError("outputs: letters, digits and commas only")

    if not d.get("red_suites") and not d.get("green_suites"):
        raise ValueError("pick at least one suite for the red or green tally")
    cmd = [sys.executable, "-u", script,
           "--port", str(_int(d, "port", 1, 65535, 2012)),
           "--red-suites", _suites(d, "red_suites"), "--green-suites", _suites(d, "green_suites"),
           "--udp-host", _host(d, "udp_host"),
           "--frame-bind", _bind(d, "frame_bind"), "--udp-bind", _bind(d, "udp_bind"),
           "--udp-port", str(_int(d, "udp_port", 1, 65535, 9999)),
           "--tsl-version", ver,
           "--tsl-screen", str(_int(d, "tsl_screen", 0, 65535, 0)),
           "--tsl-start", str(_int(d, "tsl_start", 0, 65534, 0)),
           "--tsl-count", str(_int(d, "tsl_count", 1, 65535, 128)),
           "--addr-offset", str(_int(d, "addr_offset", -65534, 65534, 0)),
           "--brightness", str(_int(d, "brightness", 0, 3, 3)),
           "--label", label,
           "--outputs", outputs,
           "--red", _buses(d, "red"), "--green", _buses(d, "green")]
    extra = _extra(d)
    if extra:
        cmd += ["--udp-extra", extra]
    if not mock:
        cmd += ["--frame-ip", _host(d, "frame_ip")]
    for key, flag in (("red_out", "--red-out"), ("green_out", "--green-out")):
        v = _outs(d, key)
        if v:
            cmd += [flag, v]
    if d.get("mode") == "dry":
        cmd.append("--dry-run")
    elif d.get("mode") != "live":
        raise ValueError("mode must be live or dry")
    for key, flag in (("include_cuts", "--include-cuts"), ("all_suites", "--all-suites"), ("mock", "--mock")):
        if d.get(key):
            cmd.append(flag)
    return cmd


def make_handler(runner, html_path):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                try:
                    with open(html_path, "rb") as f:
                        self._send(200, f.read(), "text/html; charset=utf-8")
                except OSError:
                    self._send(500, {"error": "navtally_gui.html not found next to navtally_web.py"})
            elif u.path == "/api/status":
                p = runner.proc
                self._send(200, {"running": runner.running(), "pid": p.pid if p else None,
                                 "exit_code": None if runner.running() or not p else p.returncode,
                                 "cmd": " ".join(runner.cmd[3:]) if runner.cmd else ""})
            elif u.path == "/api/interfaces":
                self._send(200, {"interfaces": list_interfaces()})
            elif u.path == "/api/log":
                try:
                    since = int(parse_qs(u.query).get("since", ["0"])[0])
                except ValueError:
                    since = 0
                lines, nxt = runner.log_since(since)
                self._send(200, {"lines": lines, "next": nxt})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            u = urlparse(self.path)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            except (ValueError, OSError):
                return self._send(400, {"error": "bad JSON"})
            if u.path == "/api/start":
                try:
                    cmd = build_cmd(runner.script, body)
                    runner.start(cmd)
                    self._send(200, {"ok": True})
                except ValueError as e:
                    self._send(400, {"error": str(e)})
                except (RuntimeError, OSError) as e:
                    self._send(409, {"error": str(e)})
            elif u.path == "/api/stop":
                self._send(200, {"ok": True, "was_running": runner.stop()})
            else:
                self._send(404, {"error": "not found"})

    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--web-host", default="127.0.0.1")
    ap.add_argument("--web-port", type=int, default=8080)
    ap.add_argument("--script", default=os.path.join(HERE, "NavTally-GVG.py"))
    ap.add_argument("--html", default=os.path.join(HERE, "navtally_gui.html"))
    a = ap.parse_args()
    runner = Runner(a.script)
    srv = ThreadingHTTPServer((a.web_host, a.web_port), make_handler(runner, a.html))
    print(f"NavTally web GUI on http://{a.web_host}:{a.web_port}  (Ctrl+C to quit)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()


if __name__ == "__main__":
    main()
