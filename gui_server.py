#!/usr/bin/env python3
"""WiFi Auditor — UI locale (backend). Réutilise auditor.py.
Lance :  python3 gui_server.py    puis ouvre http://127.0.0.1:8777
Audite TES réseaux uniquement."""
import json, os, re, signal, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import auditor  # find_wordlists, convert, essids_from_hc22000, human

HERE = Path(__file__).parent
PORT = 8777
HC_DIR = Path.home() / "Downloads" / "hc22000"


def find_rules():
    """Localise un fichier de règles hashcat (préf. rockyou-30000)."""
    import glob
    pats = ["/opt/homebrew/Cellar/hashcat/*/share/doc/hashcat/rules",
            "/opt/homebrew/share/hashcat/rules",
            "/usr/local/share/hashcat/rules", "/usr/share/hashcat/rules"]
    for pat in pats:
        for d in glob.glob(pat):
            for name in ("rockyou-30000.rule", "best64.rule", "dive.rule"):
                p = Path(d) / name
                if p.exists():
                    return str(p)
    return ""


RULES = find_rules()

STATE = {"proc": None, "log": None, "hc": None, "essid": "", "mode": ""}
LOCK = threading.Lock()


def list_caps():
    roots = [Path.home() / "Downloads"]
    v = Path("/Volumes")
    if v.exists():
        roots += [d / "BrucePCAP" / "handshakes" for d in v.iterdir()]
    caps = []
    for r in roots:
        if r.exists():
            for p in sorted(r.rglob("*.pcap")) + sorted(r.rglob("*.cap")):
                caps.append({"name": p.name, "path": str(p)})
    # + déjà convertis
    if HC_DIR.exists():
        for p in sorted(HC_DIR.glob("*.hc22000")):
            caps.append({"name": p.name, "path": str(p)})
    return caps


def list_wordlists():
    return [{"name": p.name, "path": str(p), "size": auditor.human(s),
             "big": s > 1_000_000_000} for p, s in auditor.find_wordlists()]


def ensure_hc(cap_path):
    p = Path(cap_path)
    if p.suffix == ".hc22000":
        return p, (auditor.essids_from_hc22000(p) or [""])[0]
    hc, essids = auditor.convert(p, HC_DIR)
    return hc, (essids or [""])[0]


def start(cfg):
    with LOCK:
        if STATE["proc"] and STATE["proc"].poll() is None:
            return {"error": "déjà en cours"}
    hc, essid = ensure_hc(cfg["cap"])
    if not hc:
        return {"error": "conversion échouée (handshake incomplet ?)"}
    log = hc.with_suffix(".json.log")
    log.write_text("")
    base = ["hashcat", "-m", "22000", str(hc), "-w", "3", "--potfile-disable",
            "--status", "--status-json", "--status-timer", "2"]
    if cfg["mode"] == "mask":
        if cfg.get("mask") == "FULL":
            lmin = max(1, min(20, int(cfg.get("lmin", 8))))
            lmax = max(lmin, min(20, int(cfg.get("lmax", 12))))
            cmd = base + ["-a", "3", "-i", "--increment-min", str(lmin),
                          "--increment-max", str(lmax), "?a" * lmax]
        else:
            cmd = base + ["-a", "3", cfg["mask"]]
    elif cfg["mode"] == "rules":
        if not RULES:
            return {"error": "aucun fichier de règles hashcat trouvé"}
        cmd = base + [cfg["wordlist"], "-r", RULES]
    else:
        cmd = base + [cfg["wordlist"]]
    f = open(log, "w")
    proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
    with LOCK:
        STATE.update(proc=proc, log=log, hc=hc, essid=essid, mode=cfg["mode"])
    return {"ok": True, "essid": essid}


def show_password():
    hc = STATE["hc"]
    if not hc:
        return ""
    r = subprocess.run(["hashcat", "-m", "22000", str(hc), "--show"],
                       capture_output=True, text=True)
    for line in r.stdout.strip().splitlines():
        if ":" in line:
            return line.rsplit(":", 1)[-1]
    return ""


def status():
    proc = STATE["proc"]
    if not proc:
        return {"state": "idle"}
    running = proc.poll() is None
    last = {}
    try:
        for line in STATE["log"].read_text(errors="ignore").splitlines():
            i = line.find("{")
            if i < 0:
                continue
            frag = line[i:].rstrip()
            if frag.endswith("}"):
                try:
                    last = json.loads(frag)
                except ValueError:
                    pass
    except OSError:
        pass
    out = {"state": "running" if running else "done", "essid": STATE["essid"],
           "mode": STATE["mode"]}
    if last:
        done, total = (last.get("progress") or [0, 0])[:2]
        out["pct"] = round(done * 100 / total, 2) if total else 0
        out["tested"] = done
        out["total"] = total
        out["speed"] = sum(d.get("speed", 0) for d in last.get("devices", []))
        est = last.get("estimated_stop", 0)
        out["eta"] = max(0, int(est - time.time())) if est else 0
        rec = last.get("recovered_hashes") or [0, 1]
        out["found"] = rec[0] > 0
        out["hc_status"] = last.get("status")
    if not running:
        pw = show_password()
        out["found"] = bool(pw)
        out["password"] = pw
        out["exhausted"] = not pw
    return out


def stop():
    proc = STATE["proc"]
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        time.sleep(0.5)
        if proc.poll() is None:
            proc.kill()
    return {"ok": True}


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, (HERE / "ui.html").read_bytes(), "text/html; charset=utf-8")
        elif path.startswith("/docs/"):
            f = (HERE / "docs" / Path(path).name)
            if f.parent == HERE / "docs" and f.is_file():
                self._send(200, f.read_bytes(), "image/jpeg")
            else:
                self._send(404, {"error": "not found"})
        elif path == "/api/caps":
            self._send(200, {"caps": list_caps()})
        elif path == "/api/wordlists":
            self._send(200, {"wordlists": list_wordlists()})
        elif path == "/api/status":
            self._send(200, status())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if path == "/api/start":
            self._send(200, start(body))
        elif path == "/api/stop":
            self._send(200, stop())
        else:
            self._send(404, {"error": "not found"})


if __name__ == "__main__":
    if not auditor.have("hashcat"):
        print("hashcat absent → python3 auditor.py setup"); sys.exit(1)
    print(f"WiFi Auditor UI → http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
