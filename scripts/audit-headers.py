#!/usr/bin/env python3
"""audit-headers.py -- Audite 6 en-tetes HTTP de securite d'une URL.

Envoie UN SEUL GET (jamais de requete agressive, jamais de payload) et
verifie : Content-Security-Policy, Strict-Transport-Security (HSTS),
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
Produit un score sur 100 pondere par importance, les 3 priorites de
correction et un rapport markdown avec avertissement legal en tete et pied.

Ce script est LECTURE SEULE :
  - aucune correction automatique
  - aucune modification du site cible
  - aucun scan actif / injection / payload
  - aucun monitoring continu

Refuse : les URLs non-http(s), les IP privees (127.0.0.1, 192.168.*, 10.*,
172.16-31.*, ::1...) et le hostname localhost, pour eviter tout usage abusif.

Dependances : bibliotheque standard Python uniquement (urllib, ssl, socket,
ipaddress). Python 3.8+.

Exit codes
----------
0  success  -- l'URL a repondu et le score a ete calcule
1  error    -- URL invalide, IP privee, hote injoignable, timeout ou erreur TLS
2  warning  -- le serveur a repondu mais avec un code HTTP >= 400 (analyse
               partielle, les en-tetes presents sont quand meme scores)

Examples
--------
    python audit-headers.py https://example.com
    python audit-headers.py https://example.com --output rapport.md
    python audit-headers.py https://example.com --json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

EXIT_OK, EXIT_ERROR, EXIT_WARN = 0, 1, 2

USER_AGENT = "SecurityHeadersAudit/1.0 (Searching Murphy)"
TIMEOUT = 10  # secondes, max autorise
AUTEUR = "Thomas Leroyer"
SITE_AUTEUR = "https://searching-murphy.com"

# Ponderation par importance (total = 100)
POIDS = {
    "content-security-policy": 25,
    "strict-transport-security": 20,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 15,
    "permissions-policy": 10,
}

DISCLAIMER = (
    "AVERTISSEMENT LEGAL : ce rapport est fourni a titre informatif uniquement. "
    "Il ne constitue ni un audit de securite complet, ni une garantie "
    "d'absence de vulnerabilite. L'outil n'effectue aucune action intrusive, "
    "aucune injection et aucune modification du site audite. L'usage de cet "
    "outil doit etre limite aux sites dont vous etes proprietaire ou pour "
    "lesquels vous disposez d'une autorisation explicite. L'auteur decline "
    "toute responsabilite en cas d'usage abusif ou non autorise."
)


def vlog(verbose: bool, message: str) -> None:
    if verbose:
        print("[verbose] %s" % message, file=sys.stderr)


def refuser_ip_privee(hostname: str) -> Optional[str]:
    """Retourne un message d'erreur si le hostname est local ou une IP privee."""
    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return "hostname local refuse (%s)" % hostname
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return "resolution DNS impossible pour %s" % hostname
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "adresse privee refusee (%s -> %s)" % (hostname, ip)
    return None


def analyser_headers(headers: Dict[str, str]) -> Dict[str, dict]:
    """Evalue chaque en-tete et retourne etat, valeur, points et justification."""
    resultats = {}

    # --- Content-Security-Policy (25 pts) ---
    csp = headers.get("content-security-policy", "")
    if not csp:
        resultats["content-security-policy"] = {
            "etat": "absent", "valeur": "", "points": 0,
            "justification": "En-tete absent : aucune restriction des sources de contenu."}
    elif "unsafe-inline" in csp and ("nonce-" not in csp and "sha256-" not in csp
                                     and "sha384-" not in csp and "sha512-" not in csp):
        resultats["content-security-policy"] = {
            "etat": "faible", "valeur": csp[:120], "points": 12,
            "justification": "CSP present mais 'unsafe-inline' sans nonce/hash affaiblit la protection."}
    elif "default-src" not in csp and "script-src" not in csp:
        resultats["content-security-policy"] = {
            "etat": "faible", "valeur": csp[:120], "points": 12,
            "justification": "CSP present mais sans default-src ni script-src : portee limitee."}
    else:
        resultats["content-security-policy"] = {
            "etat": "ok", "valeur": csp[:120], "points": POIDS["content-security-policy"],
            "justification": "CSP present et structure solide."}

    # --- Strict-Transport-Security / HSTS (20 pts) ---
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        resultats["strict-transport-security"] = {
            "etat": "absent", "valeur": "", "points": 0,
            "justification": "En-tete absent : pas de politique de transport strict."}
    elif "max-age" in hsts and int([p for p in hsts.replace(" ", "").split(";")
                                    if p.startswith("max-age=")][0].split("=")[1]) >= 15552000:
        resultats["strict-transport-security"] = {
            "etat": "ok", "valeur": hsts[:120], "points": POIDS["strict-transport-security"],
            "justification": "HSTS present avec max-age >= 180 jours."}
    else:
        resultats["strict-transport-security"] = {
            "etat": "faible", "valeur": hsts[:120], "points": 10,
            "justification": "HSTS present mais max-age < 180 jours ou champ incomplet."}

    # --- X-Frame-Options (15 pts) ---
    xfo = headers.get("x-frame-options", "").upper()
    if not xfo:
        resultats["x-frame-options"] = {
            "etat": "absent", "valeur": "", "points": 0,
            "justification": "En-tete absent : le site peut etre encadre (clickjacking)."}
    elif xfo in ("DENY", "SAMEORIGIN"):
        resultats["x-frame-options"] = {
            "etat": "ok", "valeur": xfo, "points": POIDS["x-frame-options"],
            "justification": "X-Frame-Options DENY ou SAMEORIGIN : anti-clickjacking actif."}
    else:
        resultats["x-frame-options"] = {
            "etat": "faible", "valeur": xfo, "points": 7,
            "justification": "X-Frame-Options present mais valeur non standard."}

    # --- X-Content-Type-Options (15 pts) ---
    xcto = headers.get("x-content-type-options", "").lower()
    if xcto == "nosniff":
        resultats["x-content-type-options"] = {
            "etat": "ok", "valeur": xcto, "points": POIDS["x-content-type-options"],
            "justification": "nosniff actif : le navigateur ne devine pas le type MIME."}
    else:
        resultats["x-content-type-options"] = {
            "etat": "absent" if not xcto else "faible", "valeur": xcto, "points": 0,
            "justification": "En-tete absent ou != nosniff : risque de MIME sniffing."}

    # --- Referrer-Policy (15 pts) ---
    rp = headers.get("referrer-policy", "").lower()
    if not rp:
        resultats["referrer-policy"] = {
            "etat": "absent", "valeur": "", "points": 0,
            "justification": "En-tete absent : le referrer par defaut peut fuir des donnees."}
    elif rp in ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"):
        resultats["referrer-policy"] = {
            "etat": "ok", "valeur": rp, "points": POIDS["referrer-policy"],
            "justification": "Politique de referrer restrictive."}
    else:
        resultats["referrer-policy"] = {
            "etat": "faible", "valeur": rp, "points": 7,
            "justification": "Politique de referrer permissive ou incomplete."}

    # --- Permissions-Policy (10 pts) ---
    pp = headers.get("permissions-policy", "")
    if not pp:
        resultats["permissions-policy"] = {
            "etat": "absent", "valeur": "", "points": 0,
            "justification": "En-tete absent : les API navigateur (cam, geo, micro...) restent ouvertes par defaut."}
    else:
        resultats["permissions-policy"] = {
            "etat": "ok", "valeur": pp[:120], "points": POIDS["permissions-policy"],
            "justification": "Permissions-Policy present."}

    return resultats


def priorites(resultats: Dict[str, dict]) -> List[str]:
    """Retourne les 3 priorites de correction (en-tetes les plus critiques)."""
    # Trier par points perdus (poids - points), puis par poids
    pertes = [(nom, POIDS[nom] - r["points"]) for nom, r in resultats.items()]
    pertes.sort(key=lambda x: (-x[1], -POIDS[x[0]]))
    top = [p for p in pertes if p[1] > 0][:3]
    if not top:
        return ["Aucune correction requise : les 6 en-tetes sont presents et bien configures."]
    messages = []
    for nom, perte in top:
        libelles = {
            "content-security-policy": "Content-Security-Policy",
            "strict-transport-security": "Strict-Transport-Security (HSTS)",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        messages.append(
            "%s : %d point(s) perdus (%s). "
            "Voir references/headers-explained.md pour la configuration recommandee."
            % (libelles[nom], perte, resultats[nom]["etat"]))
    return messages


def rapport_markdown(url: str, http_code: int, resultats: Dict[str, dict],
                     score: int, priorites_list: List[str], date_test: str) -> str:
    """Construit le rapport markdown avec disclaimers en tete et pied."""
    lignes = []
    lignes.append("# Rapport d'audit des en-tetes de securite")
    lignes.append("")
    lignes.append("> %s" % DISCLAIMER)
    lignes.append("")
    lignes.append("## Informations")
    lignes.append("")
    lignes.append("- **URL testee** : %s" % url)
    lignes.append("- **Code HTTP** : %s" % http_code)
    lignes.append("- **Test realise le %s par %s ([%s](%s))**" % (date_test, AUTEUR, SITE_AUTEUR, SITE_AUTEUR))
    lignes.append("- **Score global** : **%d / 100**" % score)
    lignes.append("")
    lignes.append("## Detail des en-tetes")
    lignes.append("")
    lignes.append("| En-tete | Etat | Points | Justification |")
    lignes.append("|---------|------|--------|---------------|")
    libelles = {
        "content-security-policy": "Content-Security-Policy",
        "strict-transport-security": "Strict-Transport-Security",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    for nom, r in resultats.items():
        valeur = r["valeur"].replace("|", "\\|") if r["valeur"] else "-"
        lignes.append("| %s | %s | %d | %s |" % (libelles[nom], r["etat"], r["points"], r["justification"]))
    lignes.append("")
    lignes.append("## 3 priorites de correction")
    lignes.append("")
    for i, p in enumerate(priorites_list, 1):
        lignes.append("%d. %s" % (i, p))
    lignes.append("")
    lignes.append("> %s" % DISCLAIMER)
    lignes.append("")
    return "\n".join(lignes)


def auditer(url: str, verbose: bool) -> Tuple[int, Dict]:
    """Effectue l'audit. Retourne (exit_code, rapport)."""
    # 1. Validation du schema
    if not url.startswith(("http://", "https://")):
        print("ERREUR : seule les URLs http(s) sont acceptees. Recu : %s" % url, file=sys.stderr)
        return EXIT_ERROR, {}

    # 2. Extraction du hostname et refus des IP privees / localhost
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    erreur = refuser_ip_privee(hostname)
    if erreur:
        print("ERREUR : %s" % erreur, file=sys.stderr)
        return EXIT_ERROR, {}

    # 3. Un seul GET, timeout 10 s, User-Agent dedie
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    ctx = ssl.create_default_context()
    vlog(verbose, "GET %s (timeout=%ds)" % (url, TIMEOUT))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            http_code = resp.getcode()
            url_finale = resp.geturl()
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        # HTTPError porte quand meme les en-tetes de la reponse
        http_code = e.code
        url_finale = url
        headers = {k.lower(): v for k, v in e.headers.items()}
        vlog(verbose, "HTTP %d recu, analyse partielle" % http_code)
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError) as e:
        print("ERREUR : impossible de joindre %s (%s)" % (url, e), file=sys.stderr)
        return EXIT_ERROR, {}

    # 4. Analyse des en-tetes et score
    resultats = analyser_headers(headers)
    score = sum(r["points"] for r in resultats.values())
    priorites_list = priorites(resultats)
    date_test = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rapport = {
        "url": url,
        "url_finale": url_finale,
        "http_code": http_code,
        "score": score,
        "date_test": date_test,
        "auteur": AUTEUR,
        "en_tetes": resultats,
        "priorites": priorites_list,
        "markdown": rapport_markdown(url, http_code, resultats, score, priorites_list, date_test),
    }

    if http_code >= 400:
        return EXIT_WARN, rapport
    return EXIT_OK, rapport


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="audit-headers.py",
        description="Audite 6 en-tetes HTTP de securite d'une URL (lecture seule, un seul GET).",
        epilog="Refuse les IP privees et localhost. Vouvoiement : rapport redige a la forme de politesse.",
    )
    parser.add_argument("url", help="URL a auditer (http:// ou https:// uniquement)")
    parser.add_argument("--output", "-o", help="Ecrire le rapport markdown dans ce fichier")
    parser.add_argument("--json", action="store_true", help="Sortie JSON (stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Sortie de debogage")
    args = parser.parse_args(argv)

    code, rapport = auditer(args.url, args.verbose)
    if code == EXIT_ERROR:
        return code

    if args.json:
        print(json.dumps({k: v for k, v in rapport.items() if k != "markdown"},
                         ensure_ascii=False, indent=2))
    else:
        print(rapport["markdown"])

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(rapport["markdown"])
            if not args.json:
                print("\nRapport ecrit dans : %s" % args.output)
        except OSError as e:
            print("ERREUR : impossible d'ecrire %s (%s)" % (args.output, e), file=sys.stderr)
            return EXIT_ERROR

    return code


if __name__ == "__main__":
    raise SystemExit(main())