#!/usr/bin/env python3
"""WiFi Auditor — UI locale (backend). Réutilise auditor.py.
Lance :  python3 gui_server.py    puis ouvre http://127.0.0.1:8777
Audite TES réseaux uniquement."""
import json, os, re, shlex, signal, subprocess, sys, threading, time
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


def hc_fields(hc):
    """(essid, bssid_colons) depuis la 1re ligne WPA du .hc22000."""
    try:
        for line in hc.read_text(errors="ignore").splitlines():
            p = line.split("*")
            if len(p) > 5 and p[0].startswith("WPA"):
                essid = bytes.fromhex(p[5]).decode("utf-8", "replace")
                mac = p[3]
                bssid = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
                return essid, bssid
    except OSError:
        pass
    return "", ""


AIR_MARK = "__AIRCRACK__"


def hc_stage(txt):
    """Libellé de l'étape hashcat avant le 1er status (compil kernels, cache…)."""
    order = [
        ("Starting autotune", "Autotune…"),
        ("self-test", "Self-test…"),
        ("Dictionary cache buil", "Caching dictionary…"),
        ("Initializing device kernels", "Compiling GPU kernels…"),
        ("Initializing backend", "Initializing GPU…"),
    ]
    stage = "Starting…"
    for key, label in order:
        if key in txt:
            stage = label
            break
    if stage == "Caching dictionary…" and "Dictionary cache built" not in txt:
        m = re.findall(r"cache building[^%(]*\(([\d.]+)%\)", txt)
        if m:
            stage += " " + m[-1] + "%"
    return stage


def attack_args(cfg):
    """Args hashcat communs à l'attaque et à --stdout (génération candidats)."""
    if cfg["mode"] == "mask":
        if cfg.get("mask") == "FULL":
            lmin = max(1, min(20, int(cfg.get("lmin", 8))))
            lmax = max(lmin, min(20, int(cfg.get("lmax", 12))))
            return ["-a", "3", "-i", "--increment-min", str(lmin),
                    "--increment-max", str(lmax), "?a" * lmax]
        return ["-a", "3", cfg["mask"]]
    if cfg["mode"] == "rules":
        return [cfg["wordlist"], "-r", RULES]
    return [cfg["wordlist"]]


def start(cfg):
    with LOCK:
        if STATE["proc"] and STATE["proc"].poll() is None:
            return {"error": "déjà en cours"}
    if cfg["mode"] == "rules" and not RULES:
        return {"error": "aucun fichier de règles hashcat trouvé"}
    hc, essid = ensure_hc(cfg["cap"])
    if not hc:
        return {"error": "conversion échouée (handshake incomplet ?)"}
    essid2, bssid = hc_fields(hc)
    essid = essid or essid2
    cap = Path(cfg["cap"])
    pcap = str(cap) if cap.suffix.lower() in (".pcap", ".pcapng", ".cap") else ""
    out = hc.with_suffix(".cracked")
    log = hc.with_suffix(".json.log")
    for f in (out, log):
        try:
            f.unlink()
        except OSError:
            pass
    engine = cfg.get("engine", "auto")   # auto | hashcat | aircrack
    if engine == "aircrack" and not (pcap and auditor.have("aircrack-ng")):
        return {"error": "aircrack (CPU) exige le .pcap d'origine + aircrack-ng"}
    aa = attack_args(cfg)
    hccmd = (["hashcat", "-m", "22000", str(hc)] + aa +
             ["-w", "3", "--potfile-disable", "--status", "--status-json",
              "--status-timer", "2", "--outfile", str(out), "--outfile-format", "2"])
    # aircrack-ng vérifie le .pcap brut ; hashcat --stdout génère les candidats (règles/masque).
    fallback = ""
    if pcap and auditor.have("aircrack-ng"):
        gen = " ".join(shlex.quote(x) for x in (["hashcat", "--stdout"] + aa))
        air = ["aircrack-ng", "-w", "-", "-e", essid] + (["-b", bssid] if bssid else []) + [pcap]
        aircmd = " ".join(shlex.quote(x) for x in air)
        fallback = "echo " + AIR_MARK + "; " + gen + " | " + aircmd
    parts = []
    if engine in ("auto", "hashcat"):
        parts.append(" ".join(shlex.quote(x) for x in hccmd))
    if engine == "aircrack":
        parts.append(fallback)
    elif engine == "auto" and fallback:
        parts.append("if [ ! -s " + shlex.quote(str(out)) + " ]; then " + fallback + "; fi")
    script = "\n".join(parts) + "\n"
    fh = open(log, "w")
    proc = subprocess.Popen(["bash", "-c", script], stdout=fh, stderr=subprocess.STDOUT)
    with LOCK:
        STATE.update(proc=proc, log=log, hc=hc, essid=essid, mode=cfg["mode"], out=out)
    return {"ok": True, "essid": essid}


def crack_result():
    """Mot de passe trouvé : outfile hashcat, sinon 'KEY FOUND' d'aircrack."""
    out = STATE.get("out")
    try:
        if out and out.exists() and out.stat().st_size:
            lines = out.read_text(errors="ignore").strip().splitlines()
            if lines:
                return lines[-1].strip()
    except OSError:
        pass
    try:
        txt = STATE["log"].read_text(errors="ignore")
        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", txt)
        if m:
            return m.group(1)
    except OSError:
        pass
    return ""


def status():
    proc = STATE["proc"]
    if not proc:
        return {"state": "idle"}
    running = proc.poll() is None
    txt = ""
    try:
        txt = STATE["log"].read_text(errors="ignore")
    except OSError:
        pass
    phase = "aircrack" if AIR_MARK in txt else "hashcat"
    last = {}
    for line in txt.splitlines():
        i = line.find("{")
        if i < 0:
            continue
        frag = line[i:].rstrip()
        if frag.endswith("}"):
            try:
                last = json.loads(frag)
            except ValueError:
                pass
    out = {"state": "running" if running else "done", "essid": STATE["essid"],
           "mode": STATE["mode"], "phase": phase}
    if running and phase == "hashcat" and not last:
        out["stage"] = hc_stage(txt)
    if last and phase == "hashcat":
        done, total = (last.get("progress") or [0, 0])[:2]
        out["pct"] = round(done * 100 / total, 2) if total else 0
        out["tested"] = done
        out["total"] = total
        out["speed"] = sum(d.get("speed", 0) for d in last.get("devices", []))
        est = last.get("estimated_stop", 0)
        out["eta"] = max(0, int(est - time.time())) if est else 0
    pw = crack_result()
    if pw:
        out["found"] = True
        out["password"] = pw
    if not running:
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
