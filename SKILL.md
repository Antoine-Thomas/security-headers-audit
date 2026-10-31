---
name: security-headers-audit
description: "Use when auditing the HTTP security headers of a website URL — scores 6 headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) out of 100 and produces a legal-markdown report with the 3 top corrections."
version: 1.0.0
author: Thomas Leroyer
tags: [security, headers, http, audit, csp, hsts, xss, clickjacking, website, hermes-agent]
category: security
price: 0
license: MIT
source: ""
security_reviewed: true
metadata:
  hermes:
    tags: [security, headers, http, audit, csp, hsts]
    category: security
    created: "2026-10-12"
---

# Security Headers Audit

Auditez en 30 secondes les 6 en-têtes HTTP de sécurité d'un site web et
obtenez un score sur 100 avec les 3 priorités de correction. Outil
gratuit, 100 % local, sans clé API, sans compte, sans cloud.

## When to use

- « Audite les en-têtes de sécurité de https://mon-site.com »
- « Quel est le score de sécurité HTTP de ce site ? »
- « Vérifie si ce site a un CSP, un HSTS, X-Frame-Options... »
- « Génère un rapport de sécurité des en-têtes HTTP »

## Pourquoi ce skill

Testé en conditions réelles sur searching-murphy.com (WordPress + o2switch) :
parti de 0/100, monté à 87/100 après configuration des en-têtes, et re-mesuré
65/100 le 31/10/2026 — CSP et Permissions-Policy ne sont plus servis
aujourd'hui. Le chiffre reproductible est 65. Le détail des
6 en-têtes, leurs pièges et la démarche de correction sont documentés
dans `references/headers-explained.md`.

## Ce que fait la skill

1. Envoie **un seul GET** (jamais de requête agressive, aucun payload).
2. Vérifie **6 en-têtes** :
   - Content-Security-Policy (25 pts)
   - Strict-Transport-Security / HSTS (20 pts)
   - X-Frame-Options (15 pts)
   - X-Content-Type-Options (15 pts)
   - Referrer-Policy (15 pts)
   - Permissions-Policy (10 pts)
3. Calcule un **score sur 100** pondéré par importance.
4. Affiche les **3 priorités de correction**.
5. Génère un **rapport markdown** avec avertissement légal en tête et pied.

## Ce que la skill ne fait PAS

- Aucun scan actif, aucune injection, aucun payload.
- Aucune correction automatique (recommandations uniquement).
- Aucune modification du site cible.
- Aucun monitoring continu.

## Utilisation

```bash
python scripts/audit-headers.py https://example.com
python scripts/audit-headers.py https://example.com --output rapport.md
python scripts/audit-headers.py https://example.com --json
```

### Options

| Option | Effet |
|--------|-------|
| `url` (positionnel) | URL à auditer — http(s) uniquement |
| `--output FILE` / `-o` | Écrit le rapport markdown dans un fichier |
| `--json` | Sortie JSON structurée |
| `--verbose` / `-v` | Sortie de débogage |

### Codes de sortie

| Code | Signification |
|------|---------------|
| 0 | Succès : l'URL a répondu, score calculé |
| 1 | Erreur : URL invalide, IP privée, hôte injoignable, timeout, erreur TLS |
| 2 | Avertissement : réponse HTTP >= 400, analyse partielle |

## Garde-fous

- **Timeout 10 s maximum** — le script ne reste jamais bloqué.
- **User-Agent dédié** : `SecurityHeadersAudit/1.0 (Searching Murphy)`.
- **Refus des IP privées** : 127.0.0.1, 192.168.*, 10.*, 172.16-31.*, ::1,
  et `localhost` — pour éviter tout usage abusif.
- **Refus des URLs non-http(s)** : `ftp://`, `file://`, etc.
- **Un seul GET** : aucune requête répétée, aucune sonde agressive.

## Exigences

- Python 3.8+ (bibliothèque standard uniquement — aucune dépendance externe)
- Accès réseau HTTPS sortant (port 443)

## Documentation

- `references/headers-explained.md` — ce que fait chaque en-tête, pourquoi,
  configuration recommandée.
- `references/score-rubric.md` — le détail du calcul du score.
- `references/legal-disclaimer.md` — l'avertissement légal et les règles
  d'usage responsable.
- `fixtures/sample-report.md` — un exemple de rapport généré.

## Sécurité

- Aucune clé API, aucun compte, aucun service cloud.
- Aucun secret stocké ou transmis : le script ne fait qu'un GET HTTP.
- Aucune variable d'environnement lue.
- Aucune écriture hors du fichier `--output` explicitement demandé.

## Licence

MIT — gratuit, usage personnel et commercial autorisé. Conservez la mention
de l'auteur dans les rapports générés.

## Contact

Thomas Leroyer — https://searching-murphy.com
