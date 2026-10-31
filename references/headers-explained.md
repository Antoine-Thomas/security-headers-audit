# Les 6 en-têtes de sécurité — ce qu'ils font et pourquoi

Ce document explique, pour chaque en-tête audité par `audit-headers.py`,
ce qu'il protège, comment le configurer, et ce qu'une absence implique.

---

## 1. Content-Security-Policy (CSP) — 25 points

**Ce que c'est** : une liste blanche des sources autorisées pour les
scripts, styles, images, frames et connexions d'une page.

**Ce que ça protège** : contre l'injection de contenu — XSS (cross-site
scripting), injection de scripts malveillants, exfiltration de données.
C'est l'en-tête le plus important de la liste.

**Configuration minimale recommandée** :

```
Content-Security-Policy: default-src 'self'; script-src 'self';
                         style-src 'self'; img-src 'self' data:;
                         object-src 'none'; base-uri 'self'
```

**Pieges** :
- `'unsafe-inline'` dans `script-src` sans nonce ou hash annule une grande
  partie de la protection.
- Absence de `default-src` ou `script-src` = portée très limitée.
- Un CSP trop strict casse le site : testez avant de déployer.

---

## 2. Strict-Transport-Security (HSTS) — 20 points

**Ce que c'est** : une directive qui ordonne au navigateur de n'utiliser
QUE HTTPS pour ce domaine pendant une durée donnée.

**Ce que ça protège** : contre le déclassement HTTPS→HTTP (SSL stripping)
et les attaques de l'homme du milieu sur la première connexion.

**Configuration minimale recommandée** :

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

`max-age` est en secondes. 31536000 = 1 an ; le seuil de l'audit est
15552000 (180 jours).

**Pieges** :
- `max-age` trop court = protection éphémère.
- `includeSubDomains` doit être ajouté une fois le HTTPS généralisé, sinon
  les sous-domaines restent vulnérables.

---

## 3. X-Frame-Options — 15 points

**Ce que c'est** : interdit (ou restreint) l'affichage de la page dans une
frame / un iframe d'un autre site.

**Ce que ça protège** : contre le clickjacking — un attaquant encadre votre
page dans un site piège et incite l'utilisateur à cliquer à son insu.

**Configuration recommandée** :

```
X-Frame-Options: DENY            # ou SAMEORIGIN si des frames internes existent
```

**Pieges** : `ALLOW-FROM` est déprécié ; préférez le header CSP
`frame-ancestors` pour un contrôle fin (les deux peuvent coexister).

---

## 4. X-Content-Type-Options — 15 points

**Ce que c'est** : la valeur unique `nosniff` ordonne au navigateur de ne
pas deviner le type MIME d'une ressource.

**Ce que ça protège** : contre le MIME sniffing — un attaquant qui sert un
fichier `.txt` contenant du HTML/JS peut voir son contenu exécuté comme du
contenu actif.

**Configuration recommandée** :

```
X-Content-Type-Options: nosniff
```

**Pieges** : toute valeur autre que `nosniff` est inutile (l'en-tête n'a
pas d'autre valeur standard).

---

## 5. Referrer-Policy — 15 points

**Ce que c'est** : contrôle les informations envoyées dans l'en-tête
`Referer` lors des navigations sortantes.

**Ce que ça protège** : contre la fuite de l'URL complète (avec query
strings, tokens, identifiants de session) vers des sites tiers.

**Configuration recommandée** (par ordre de restriction) :

```
Referrer-Policy: strict-origin-when-cross-origin   # bon compromis par défaut
Referrer-Policy: same-origin                        # plus restrictif
Referrer-Policy: no-referrer                        # le plus restrictif
```

**Pieges** : `unsafe-url` envoie l'URL complète à tous les destinataires —
à éviter.

---

## 6. Permissions-Policy — 10 points

**Ce que c'est** : contrôle l'accès des pages (et de leurs frames) aux API
navigateur : caméra, microphone, géolocalisation, notifications...

**Ce que ça protège** : contre l'exploitation silencieuse des permissions
par du contenu embarqué (frames tierces) ou compromis.

**Configuration minimale recommandée** :

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

**Pieges** : un en-tête présent mais qui autorise tout (`*`) n'apporte
aucune protection réelle.

---

## Ordre de priorité

1. **Content-Security-Policy** (25 pts) — la protection la plus structurante.
2. **Strict-Transport-Security** (20 pts) — verrouille le canal HTTPS.
3. **X-Frame-Options** (15 pts) — anti-clickjacking immédiat.
4. **X-Content-Type-Options** (15 pts) — réglage trivial, souvent oublié.
5. **Referrer-Policy** (15 pts) — limite les fuites d'URL.
6. **Permissions-Policy** (10 pts) — restreint les API navigateur.

Le détail du calcul du score : voir `score-rubric.md`.