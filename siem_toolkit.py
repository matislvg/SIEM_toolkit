#!/usr/bin/env python3
"""
SIEM Toolkit — Stage Valabre
Mission 2 : Analyse de logs, VirusTotal, Scapy

Version fusionnée :
- Lecture des logs en streaming (optimisation mémoire)
- Support clé API via variable d'environnement
- Gestion des privilèges pour le module Scapy
- Gestion propre du KeyboardInterrupt
"""

import os
import re
import sys
import json
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict


# ─────────────────────────────────────────────
#  COULEURS TERMINAL
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════╗
║          SIEM TOOLKIT — Stage Valabre        ║
║          Mission 2 : Analyse & Détection     ║
╚══════════════════════════════════════════════╝{C.RESET}""")

def menu():
    print(f"""
{C.BOLD}Que veux-tu faire ?{C.RESET}

  {C.GREEN}[1]{C.RESET} 📊  Analyser un fichier access.log
  {C.GREEN}[2]{C.RESET} 🔍  Vérifier une IP sur VirusTotal
  {C.GREEN}[3]{C.RESET} 🛠️   Générer du trafic réseau avec Scapy
  {C.GREEN}[0]{C.RESET} ❌  Quitter
""")


# ─────────────────────────────────────────────
#  MODULE 1 — ANALYSE ACCESS.LOG
# ─────────────────────────────────────────────

# Extraction rapide de l'IP en début de ligne
IP_PATTERN = re.compile(r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# Regex format Combined Log (nginx/apache) — permissive pour compatibilité max
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r'.+?'
    r'"(?P<method>\w+)\s(?P<path>\S*)\s\S+"'
    r'\s(?P<status>\d{3})'
    r'\s(?P<size>\d+|-)'
)

# Patterns de détection d'attaques
ATTACK_PATTERNS = {
    "Injection SQL"               : re.compile(r"(union.*select|select.*from|or.*=|--|%27|%3D|0x)", re.I),
    "LFI / Path Traversal"        : re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd|/etc/shadow)", re.I),
    "XSS"                         : re.compile(r"(<script|javascript:|onerror=|%3cscript)", re.I),
    "Scanner (nikto/sqlmap/nmap)" : re.compile(r"(nikto|sqlmap|nmap|masscan|zgrab)", re.I),
    "Brute force login"           : re.compile(r"(wp-login|admin/login|/login|/signin)", re.I),
    "Webshell"                    : re.compile(r"(cmd=|exec=|system\(|passthru|base64_decode)", re.I),
}

def analyse_logs():
    print(f"\n{C.BOLD}📊 Analyse du fichier access.log{C.RESET}")
    path = input("  Chemin du fichier [access.log] : ").strip() or "access.log"

    if not os.path.exists(path):
        print(f"{C.RED}  ✗ Fichier introuvable : {path}{C.RESET}")
        return

    print(f"\n  {C.GREEN}✓{C.RESET} Début de l'analyse en streaming...\n")

    ip_counter     = Counter()
    status_counter = Counter()
    attack_hits    = defaultdict(set)   # {type_attaque: {ip, ...}}
    errors_404     = Counter()
    total_lines    = 0
    total_parsed   = 0

    # Lecture ligne par ligne — empreinte mémoire constante quelle que soit la taille du fichier
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1

            # 1. Tentative de parsing complet (Format Standard Combined Log)
            m = LOG_PATTERN.search(line)
            if m:
                total_parsed += 1
                ip = m.group("ip")
                status = m.group("status")

                ip_counter[ip] += 1
                status_counter[status] += 1

                if status == "404":
                    errors_404[ip] += 1
            else:
                # 2. Plan B : Si la ligne n'est pas standard, on extrait quand même l'IP pour ne pas la rater
                ip_match = IP_PATTERN.match(line)
                if ip_match:
                    ip = ip_match.group("ip")
                else:
                    # S'il n'y a vraiment pas d'IP au début, on ignore la ligne (ex: ligne vide, log corrompu)
                    continue

            # 3. Détection des signatures d'attaques (appliquée à toutes les IPs trouvées, plan A ou B)
            for attack_name, pattern in ATTACK_PATTERNS.items():
                if pattern.search(line):
                    attack_hits[attack_name].add(ip)

    print(f"  Lignes lues    : {total_lines:,}")
    print(f"  Lignes parsées : {total_parsed:,}\n")

    if not ip_counter and not attack_hits:
        print(f"{C.YELLOW}  ⚠ Aucune donnée exploitable ou attaque trouvée.{C.RESET}\n")
        return

    # ── Top 10 IPs ──
    print(f"{C.BOLD}  ┌─ Top 10 IPs les plus actives ─────────────────┐{C.RESET}")
    for i, (ip, count) in enumerate(ip_counter.most_common(10), 1):
        bar = "█" * min(count // 50, 40)
        print(f"  │ {i:>2}. {ip:<18} {count:>6} req   {C.CYAN}{bar}{C.RESET}")
    print(f"{C.BOLD}  └────────────────────────────────────────────────┘{C.RESET}\n")

    # ── Codes HTTP ──
    print(f"{C.BOLD}  ┌─ Répartition des codes HTTP ───────────────────┐{C.RESET}")
    for status, count in sorted(status_counter.items()):
        color = C.GREEN if status.startswith("2") else \
                C.YELLOW if status.startswith("3") else \
                C.RED
        print(f"  │  HTTP {color}{status}{C.RESET}  →  {count:,} requêtes")
    print(f"{C.BOLD}  └────────────────────────────────────────────────┘{C.RESET}\n")

    # ── IPs avec beaucoup de 404 (scan potentiel) ──
    top404 = errors_404.most_common(5)
    if top404:
        print(f"{C.BOLD}  ┌─ Top 5 IPs avec erreurs 404 (scan ?) ─────────┐{C.RESET}")
        for ip, count in top404:
            print(f"  │  {ip:<18}  {C.YELLOW}{count} × 404{C.RESET}")
        print(f"{C.BOLD}  └────────────────────────────────────────────────┘{C.RESET}\n")

    # ── Attaques détectées ──
    print(f"{C.BOLD}  ┌─ Attaques détectées ───────────────────────────┐{C.RESET}")
    if not attack_hits:
        print(f"  │  {C.GREEN}Aucune attaque détectée.{C.RESET}")
    else:
        for attack, ips in attack_hits.items():
            print(f"  │  {C.RED}[!]{C.RESET} {attack}")
            for ip in sorted(ips)[:10]:   # Limité aux 10 premières IPs
                print(f"  │       → {ip}")
            if len(ips) > 10:
                print(f"  │       → ... et {len(ips) - 10} autres IPs.")
    print(f"{C.BOLD}  └────────────────────────────────────────────────┘{C.RESET}\n")

    # ── Export optionnel ──
    export = input("  Exporter le rapport en JSON ? [o/N] : ").strip().lower()
    if export == "o":
        report = {
            "total_lines"     : total_lines,
            "parsed_lines"    : total_parsed,
            "top10_ips"       : ip_counter.most_common(10),
            "http_status"     : dict(status_counter),
            "top5_404_ips"    : top404,
            "attacks_detected": {k: list(v) for k, v in attack_hits.items()},
        }
        out = "rapport_logs.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  {C.GREEN}✓ Rapport exporté → {out}{C.RESET}\n")


# ─────────────────────────────────────────────
#  MODULE 2 — VIRUSTOTAL
# ─────────────────────────────────────────────

def check_virustotal():
    print(f"\n{C.BOLD}🔍 Vérification VirusTotal{C.RESET}")

    # Récupération via variable d'environnement ou saisie manuelle
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        api_key = input("  Clé API VirusTotal (ou configurer VIRUSTOTAL_API_KEY) : ").strip()
    else:
        print(f"  {C.GREEN}✓{C.RESET} Clé API chargée depuis les variables d'environnement.")

    if not api_key:
        print(f"{C.RED}  ✗ Clé API requise.{C.RESET}")
        return

    ip = input("  IP à analyser : ").strip()
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        print(f"{C.RED}  ✗ Format d'IP invalide.{C.RESET}")
        return

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})

    print(f"\n  Interrogation de VirusTotal pour {C.CYAN}{ip}{C.RESET}...")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(f"{C.RED}  ✗ Clé API invalide ou expirée.{C.RESET}")
        elif e.code == 404:
            print(f"{C.YELLOW}  ⚠ IP non trouvée dans la base VirusTotal.{C.RESET}")
        else:
            print(f"{C.RED}  ✗ Erreur HTTP {e.code}{C.RESET}")
        return
    except Exception as e:
        print(f"{C.RED}  ✗ Erreur réseau : {e}{C.RESET}")
        return

    attrs    = data.get("data", {}).get("attributes", {})
    stats    = attrs.get("last_analysis_stats", {})
    votes    = attrs.get("total_votes", {})
    country  = attrs.get("country", "Inconnu")
    asn      = attrs.get("asn", "?")
    as_owner = attrs.get("as_owner", "?")
    rep      = attrs.get("reputation", 0)

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    if malicious >= 5:
        verdict = f"{C.RED}⛔  MALVEILLANTE{C.RESET}"
    elif malicious >= 1 or suspicious >= 3:
        verdict = f"{C.YELLOW}⚠️   SUSPECTE{C.RESET}"
    else:
        verdict = f"{C.GREEN}✅  PROPRE{C.RESET}"

    print(f"""
  ┌─ Résultat VirusTotal ─────────────────────────┐
  │  IP          : {ip}
  │  Pays        : {country}
  │  ASN         : AS{asn} — {as_owner}
  │  Réputation  : {rep}
  ├───────────────────────────────────────────────┤
  │  Analyse ({total} moteurs) :
  │    Malveillant  : {C.RED}{malicious}{C.RESET}
  │    Suspect      : {C.YELLOW}{suspicious}{C.RESET}
  │    Sain         : {C.GREEN}{harmless}{C.RESET}
  │    Non détecté  : {undetected}
  ├───────────────────────────────────────────────┤
  │  Votes communauté : 👍 {votes.get('harmless',0)}  👎 {votes.get('malicious',0)}
  ├───────────────────────────────────────────────┤
  │  Verdict : {verdict}
  └───────────────────────────────────────────────┘
""")

    results = attrs.get("last_analysis_results", {})
    flagged = [(engine, r["result"]) for engine, r in results.items()
               if r.get("category") in ("malicious", "suspicious")]
    if flagged:
        print(f"  {C.BOLD}Moteurs ayant signalé l'IP :{C.RESET}")
        for engine, result in sorted(flagged):
            print(f"    • {engine:<25} → {C.RED}{result}{C.RESET}")
        print()


# ─────────────────────────────────────────────
#  MODULE 3 — SCAPY
# ─────────────────────────────────────────────

def scapy_module():
    print(f"\n{C.BOLD}🛠️  Module Scapy{C.RESET}")

    # Vérification des privilèges root sur Linux/macOS
    if os.name == 'posix' and os.geteuid() != 0:
        print(f"{C.RED}  ✗ Erreur de privilèges : Ce module nécessite les droits administrateur.{C.RESET}")
        print(f"  Relance le script avec : {C.CYAN}sudo python3 {sys.argv[0]}{C.RESET}\n")
        return

    try:
        from scapy.all import IP, ICMP, ARP, Ether, send, sendp, conf
        conf.verb = 0
    except ImportError:
        print(f"{C.RED}  ✗ Scapy non installé.{C.RESET}")
        print(f"  Installe-le avec : {C.CYAN}pip install scapy{C.RESET}\n")
        return

    print(f"""
  Choisir une action :

  {C.GREEN}[1]{C.RESET} ICMP malformé (ping avec payload corrompu)
  {C.GREEN}[2]{C.RESET} Flood ARP (fausses réponses ARP)
  {C.GREEN}[3]{C.RESET} Retour au menu principal
""")
    choix = input("  Choix : ").strip()

    if choix == "1":
        _scapy_icmp_malformed(IP, ICMP, send)
    elif choix == "2":
        _scapy_arp_flood(ARP, Ether, sendp)
    elif choix == "3":
        return
    else:
        print(f"{C.YELLOW}  Choix invalide.{C.RESET}")


def _scapy_icmp_malformed(IP, ICMP, send):
    print(f"\n{C.BOLD}  ICMP malformé{C.RESET}")
    target = input("  IP cible (VM) : ").strip()
    if not target:
        return
    count = int(input("  Nombre de paquets [10] : ").strip() or "10")

    print(f"\n  Envoi de {count} paquets ICMP malformés vers {C.CYAN}{target}{C.RESET}...")

    pkt = IP(dst=target) / ICMP(type=99, code=0) / (b"\x00\xFF" * 20)

    for i in range(count):
        send(pkt)
        print(f"  [{i+1}/{count}] Paquet envoyé", end="\r")
        time.sleep(0.1)

    print(f"\n  {C.GREEN}✓ {count} paquets ICMP malformés envoyés.{C.RESET}")
    print(f"  → Vérifie dans Wazuh si une alerte remonte (règles ICMP / IDS)\n")


def _scapy_arp_flood(ARP, Ether, sendp):
    print(f"\n{C.BOLD}  Flood ARP (fausses réponses){C.RESET}")
    target_ip = input("  IP cible (victime) : ").strip()
    spoof_ip  = input("  IP à usurper (ex: gateway) : ").strip()
    if not target_ip or not spoof_ip:
        return
    iface = input("  Interface réseau [eth0] : ").strip() or "eth0"
    count = int(input("  Nombre de paquets [20] : ").strip() or "20")

    print(f"\n  Envoi de {count} fausses réponses ARP...")
    print(f"  On fait croire que {C.CYAN}{spoof_ip}{C.RESET} a notre MAC.\n")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        pdst=target_ip,
        psrc=spoof_ip,
    )

    for i in range(count):
        try:
            sendp(pkt, iface=iface)
            print(f"  [{i+1}/{count}] ARP reply envoyé", end="\r")
            time.sleep(0.05)
        except Exception as e:
            print(f"\n{C.RED}  ✗ Erreur d'envoi sur l'interface {iface} : {e}{C.RESET}")
            return

    print(f"\n  {C.GREEN}✓ {count} paquets ARP envoyés.{C.RESET}")
    print(f"  → Arpwatch devrait détecter le changement de MAC et alerter Wazuh (Rule 7209)\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    banner()
    while True:
        try:
            menu()
            choix = input("  Ton choix : ").strip()
            if choix == "1":
                analyse_logs()
            elif choix == "2":
                check_virustotal()
            elif choix == "3":
                scapy_module()
            elif choix == "0":
                print(f"\n  {C.CYAN}À bientôt !{C.RESET}\n")
                sys.exit(0)
            else:
                print(f"\n{C.YELLOW}  Choix invalide, réessaie.{C.RESET}")
        except KeyboardInterrupt:
            print(f"\n\n  {C.YELLOW}Interruption détectée. Fin du programme.{C.RESET}\n")
            sys.exit(0)

if __name__ == "__main__":
    main()