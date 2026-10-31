# Barème du score — comment le score /100 est calculé

Le score reflète la présence ET la qualité de chaque en-tête, pondérées
par leur importance en sécurité. Total maximum : 100 points.

## Pondération

| En-tête | Poids | Pourquoi |
|---------|-------|----------|
| Content-Security-Policy | 25 | Protection structurante contre XSS et injection |
| Strict-Transport-Security | 20 | Verrouille le canal HTTPS |
| X-Frame-Options | 15 | Anti-clickjacking |
| X-Content-Type-Options | 15 | Anti-MIME-sniffing (réglage trivial) |
| Referrer-Policy | 15 | Limite les fuites d'URL |
| Permissions-Policy | 10 | Restreint les API navigateur |

## Règles d'attribution des points

### Content-Security-Policy (0 / 12 / 25)
- **0** : en-tête absent.
- **12** : présent mais affaibli — `unsafe-inline` dans `script-src` sans
  nonce/hash, OU absence de `default-src` et de `script-src`.
- **25** : présent avec une structure solide (`default-src` ou `script-src`,
  pas d'`unsafe-inline` nu).

### Strict-Transport-Security (0 / 10 / 20)
- **0** : en-tête absent.
- **10** : présent mais `max-age` < 15552000 (180 jours) ou champ incomplet.
- **20** : présent avec `max-age` >= 15552000.

### X-Frame-Options (0 / 7 / 15)
- **0** : en-tête absent.
- **7** : présent mais valeur non standard (ni `DENY`, ni `SAMEORIGIN`).
- **15** : `DENY` ou `SAMEORIGIN`.

### X-Content-Type-Options (0 / 15)
- **0** : absent ou valeur != `nosniff`.
- **15** : `nosniff`.

### Referrer-Policy (0 / 7 / 15)
- **0** : en-tête absent.
- **7** : présent mais politique permissive (`unsafe-url`, valeur inconnue).
- **15** : `no-referrer`, `same-origin`, `strict-origin` ou
  `strict-origin-when-cross-origin`.

### Permissions-Policy (0 / 10)
- **0** : en-tête absent.
- **10** : présent (toute valeur).

## Règle d'évaluation

Le score est **purement informatif** : il mesure la configuration des
en-têtes, pas la sécurité globale du site. Un score élevé ne garantit pas
l'absence de vulnérabilités applicatives ; un score faible ne signifie pas
que le site est compromis — il signale des protections de premier niveau
manquantes.

## Les 3 priorités de correction

Le script sélectionne les 3 en-têtes qui font perdre le plus de points
(tri par points perdus, puis par poids). À score égal, la priorité va au
poids le plus élevé. Si les 6 en-têtes sont présents et bien configurés,
le script l'indique explicitement.