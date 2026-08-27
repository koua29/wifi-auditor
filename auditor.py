#!/usr/bin/env python3
"""
WiFi Auditor — Phase 1 "handoff kit"
====================================
Chaîne côté Mac pour auditer TES PROPRES réseaux WPA/WPA2 à partir des
handshakes capturés par le LilyGO (Bruce firmware).

Flux :
    .cap/.pcap (SD du LilyGO)  ->  .hc22000  ->  Hashcat (Metal GPU)  ->  clé

Le LilyGO capture ; le Mac casse. Ce script ne fait AUCUNE capture réseau :
il ne lit que des fichiers déjà présents.

⚠️  LÉGAL : n'utilise cet outil que sur des réseaux qui t'appartiennent, ou
    pour lesquels tu as une autorisation écrite. Cracker le WiFi d'autrui est
    un délit (art. 323-1 s. du Code pénal en France).

Aucune dépendance pip. Requiert (installables via `auditor.py setup`) :
    - hcxtools  (hcxpcapngtool)   -> conversion cap -> hc22000
    - hashcat                     -> crack GPU (mode 22000)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# --- présentation ----------------------------------------------------------
C = {
    "r": "\033[0m", "b": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "grn": "\033[32m", "ylw": "\033[33m",
    "blu": "\033[34m", "cyn": "\033[36m", "mag": "\033[35m",
}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def banner():
    print(f"{C['cyn']}{C['b']}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   WiFi Auditor · handoff kit  (LilyGO → Mac)  ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(f"{C['r']}{C['dim']}  Audite TES réseaux uniquement — usage autorisé requis.{C['r']}\n")


def info(m):  print(f"  {C['blu']}ℹ{C['r']}  {m}")
def ok(m):    print(f"  {C['grn']}✔{C['r']}  {m}")
def warn(m):  print(f"  {C['ylw']}⚠{C['r']}  {m}")
def err(m):   print(f"  {C['red']}✗{C['r']}  {m}")
def step(m):  print(f"\n{C['mag']}{C['b']}▸ {m}{C['r']}")


# --- outils externes -------------------------------------------------------
def have(tool):
    return shutil.which(tool) is not None


def check_tools(require=True):
    tools = {"hcxpcapngtool": "hcxtools", "hashcat": "hashcat"}
    missing = [pkg for exe, pkg in tools.items() if not have(exe)]
    for exe, pkg in tools.items():
        (ok if have(exe) else warn)(
            f"{exe:<16} {'trouvé' if have(exe) else 'ABSENT (brew install ' + pkg + ')'}")
    if missing and require:
        err("Outils manquants. Lance :  " + C["b"] + "python3 auditor.py setup" + C["r"])
        sys.exit(1)
    return not missing


def cmd_setup(_args):
    step("Installation des dépendances (Homebrew)")
    if not have("brew"):
        err("Homebrew introuvable. Installe-le : https://brew.sh")
        sys.exit(1)
    pkgs = []
    if not have("hcxpcapngtool"): pkgs.append("hcxtools")
    if not have("hashcat"):       pkgs.append("hashcat")
    if not pkgs:
        ok("Tout est déjà installé.")
        return
    info("À installer : " + ", ".join(pkgs))
    print(f"\n  {C['b']}brew install {' '.join(pkgs)}{C['r']}\n")
    r = input("  Lancer l'installation maintenant ? [o/N] ").strip().lower()
    if r not in ("o", "y", "oui"):
        info("Annulé. Tu peux copier la commande ci-dessus et la lancer toi-même.")
        return
    subprocess.run(["brew", "install", *pkgs], check=False)
    check_tools(require=False)


# --- découverte des captures ----------------------------------------------
CAP_EXT = (".cap", ".pcap", ".pcapng")


def find_caps(target: Path):
    if target.is_file():
        return [target] if target.suffix.lower() in CAP_EXT else []
    return sorted(p for p in target.rglob("*") if p.suffix.lower() in CAP_EXT)


def guess_sd():
    """Cherche un dossier de handshakes plausible (SD montée, Downloads…)."""
    cands = []
    vol = Path("/Volumes")
    subs = ("BrucePCAP/handshakes", "BrucePCAP", "handshakes",
            "sniffer", "captures")
    if vol.exists():
        for d in vol.iterdir():
            for sub in subs:
                p = d / sub
                if p.is_dir():
                    cands.append(p)
            if list(d.rglob("*.pcap"))[:1] or list(d.rglob("*.cap"))[:1]:
                cands.append(d)
    return cands


# --- conversion ------------------------------------------------------------
def essids_from_hc22000(hc: Path):
    """Décode les ESSID (champ 6, hex) des lignes WPA*… du .hc22000."""
    out = []
    try:
        for line in hc.read_text(errors="ignore").splitlines():
            parts = line.split("*")
            if len(parts) > 5 and parts[0].startswith("WPA"):
                try:
                    out.append(bytes.fromhex(parts[5]).decode("utf-8", "replace"))
                except ValueError:
                    pass
    except OSError:
        pass
    return sorted(set(out))


def convert(cap: Path, out_dir: Path):
    """cap/pcap -> hc22000. Retourne (hc22000_path, essid_list) ou (None, [])."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / (cap.stem + ".hc22000")
    subprocess.run(["hcxpcapngtool", "-o", str(out), str(cap)],
                   capture_output=True, text=True)
    if out.exists() and out.stat().st_size > 0:
        return out, essids_from_hc22000(out)
    return None, []


# --- wordlists -------------------------------------------------------------
def find_wordlists():
    """Liste (chemin, taille) des dicos plausibles sur la machine."""
    seen, found = set(), []
    roots = [Path.home() / "Downloads", Path.home() / "Documents",
             Path(__file__).parent / "wordlists"]
    hints = ("weakpass", "crackstation", "rockyou", "wordlist", "wifi", "wpa")
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*.txt"):
            if p in seen:
                continue
            seen.add(p)
            name = p.name.lower()
            sz = p.stat().st_size
            local = (Path(__file__).parent / "wordlists") in p.parents
            if local or any(h in name for h in hints) or sz > 5_000_000:
                found.append((p, sz))
    return sorted(found, key=lambda t: -t[1])


def human(n):
    for u in ("o", "Ko", "Mo", "Go"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.1f} To"


def pick_wordlist(preferred=None):
    if preferred:
        p = Path(preferred).expanduser()
        if p.exists():
            return p
        err(f"Wordlist introuvable : {preferred}")
        sys.exit(1)
    wl = find_wordlists()
    if not wl:
        err("Aucune wordlist trouvée. Récupère par ex. weakpass_2_wifi "
            "(https://weakpass.com) et relance avec --wordlist <fichier>.")
        sys.exit(1)
    step("Wordlists détectées")
    for i, (p, sz) in enumerate(wl, 1):
        tag = ""
        if sz > 1_000_000_000: tag = f"{C['ylw']}(Mac only — trop gros pour LilyGO){C['r']}"
        print(f"   {C['b']}{i}{C['r']}. {p.name}  {C['dim']}{human(sz)}{C['r']}  {tag}")
    while True:
        r = input(f"\n  Choix [1-{len(wl)}, défaut 1] : ").strip() or "1"
        if r.isdigit() and 1 <= int(r) <= len(wl):
            return wl[int(r) - 1][0]


# --- génération du script portable ----------------------------------------
def write_crack_sh(hc: Path, wordlist: Path, essids):
    sh = hc.with_suffix(".crack.sh")
    ess = ", ".join(essids) if essids else "?"
    sh.write_text(f"""#!/usr/bin/env bash
# Auto-généré par WiFi Auditor — crack de : {ess}
# Réseau audité sous ta responsabilité (autorisation requise).
set -e
HC="{hc.name}"
WL="{wordlist}"
echo "▸ Hashcat mode 22000 (WPA) sur $HC"
hashcat -m 22000 "$HC" "$WL" --status --status-timer 10
echo "▸ Clés trouvées :"
hashcat -m 22000 "$HC" --show
""")
    sh.chmod(0o755)
    return sh


# --- commandes principales -------------------------------------------------
def cmd_scan(args):
    check_tools()
    target = Path(args.path).expanduser() if args.path else None
    if target is None:
        sds = guess_sd()
        if sds:
            info("SD/handshakes détectés :")
            for s in sds:
                print(f"     {C['dim']}{s}{C['r']}")
            target = sds[0]
        else:
            err("Aucun dossier de capture trouvé. Précise un chemin : "
                "auditor.py scan /Volumes/…/handshakes")
            sys.exit(1)
    caps = find_caps(target)
    if not caps:
        err(f"Aucune capture (.cap/.pcap) sous {target}")
        sys.exit(1)
    step(f"{len(caps)} capture(s) trouvée(s) sous {target}")
    out_dir = Path(args.out).expanduser() if args.out else target.parent / "hc22000"
    good = []
    for cap in caps:
        hc, essids = convert(cap, out_dir)
        label = f"{cap.name}"
        if hc:
            ok(f"{label:<28} → {hc.name}   {C['dim']}ESSID: {', '.join(essids) or '?'}{C['r']}")
            good.append((hc, essids))
        else:
            warn(f"{label:<28} handshake incomplet / non convertible")
    if not good:
        err("Aucun handshake exploitable. Recapture (attendre un vrai 4-way).")
        sys.exit(1)
    ok(f"{len(good)} handshake(s) prêt(s) dans {out_dir}")
    info("Étape suivante :  " + C["b"] + "python3 auditor.py crack " + str(out_dir) + C["r"])


def cmd_crack(args):
    check_tools()
    target = Path(args.path).expanduser()
    hcs = sorted(target.rglob("*.hc22000")) if target.is_dir() else [target]
    hcs = [p for p in hcs if p.exists()]
    if not hcs:
        err("Aucun .hc22000. Lance d'abord :  python3 auditor.py scan …")
        sys.exit(1)
    wordlist = pick_wordlist(args.wordlist)
    step(f"Crack de {len(hcs)} handshake(s) avec {wordlist.name}")
    for hc in hcs:
        print(f"\n{C['b']}── {hc.name} ──{C['r']}")
        if args.prep_only:
            sh = write_crack_sh(hc, wordlist, [])
            ok(f"Script prêt (non lancé) : {sh}")
            continue
        subprocess.run(["hashcat", "-m", "22000", str(hc), str(wordlist),
                        "--status", "--status-timer", "10"], check=False)
        print(f"{C['grn']}{C['b']}Résultat :{C['r']}")
        subprocess.run(["hashcat", "-m", "22000", str(hc), "--show"], check=False)


def cmd_prep(args):
    """Convertit + génère les crack.sh portables, sans lancer le crack."""
    check_tools()
    target = Path(args.path).expanduser()
    caps = find_caps(target)
    if not caps:
        err(f"Aucune capture sous {target}"); sys.exit(1)
    out_dir = Path(args.out).expanduser() if args.out else target.parent / "hc22000"
    wordlist = pick_wordlist(args.wordlist)
    step("Préparation des scripts portables")
    for cap in caps:
        hc, essids = convert(cap, out_dir)
        if not hc:
            warn(f"{cap.name} : non convertible"); continue
        sh = write_crack_sh(hc, wordlist, essids)
        ok(f"{cap.name} → {hc.name} + {sh.name}")
    info(f"Copie {out_dir} sur la machine GPU et lance chaque *.crack.sh")


def main():
    p = argparse.ArgumentParser(
        description="WiFi Auditor — capture LilyGO → crack Mac (audit autorisé).")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("setup", help="installe hcxtools + hashcat via brew")
    sp.set_defaults(func=cmd_setup)

    sp = sub.add_parser("scan", help="convertit les .cap/.pcap en .hc22000")
    sp.add_argument("path", nargs="?", help="dossier/fichier (défaut: auto-détection SD)")
    sp.add_argument("--out", help="dossier de sortie des .hc22000")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("crack", help="lance Hashcat sur les .hc22000")
    sp.add_argument("path", help="dossier ou fichier .hc22000")
    sp.add_argument("--wordlist", help="chemin d'un dictionnaire")
    sp.add_argument("--prep-only", action="store_true",
                    help="génère les scripts sans lancer le crack")
    sp.set_defaults(func=cmd_crack)

    sp = sub.add_parser("prep", help="convertit + génère les crack.sh portables")
    sp.add_argument("path", help="dossier/fichier de captures")
    sp.add_argument("--out", help="dossier de sortie")
    sp.add_argument("--wordlist", help="chemin d'un dictionnaire")
    sp.set_defaults(func=cmd_prep)

    args = p.parse_args()
    banner()
    if not getattr(args, "func", None):
        check_tools(require=False)
        print()
        p.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
