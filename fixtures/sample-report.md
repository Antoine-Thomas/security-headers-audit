# Rapport d'audit des en-têtes de sécurité

> AVERTISSEMENT LÉGAL : ce rapport est fourni à titre informatif uniquement.
> Il ne constitue ni un audit de sécurité complet, ni une garantie d'absence
> de vulnérabilité. L'outil n'effectue aucune action intrusive, aucune
> injection et aucune modification du site audité. L'usage de cet outil doit
> être limité aux sites dont vous êtes propriétaire ou pour lesquels vous
> disposez d'une autorisation explicite. L'auteur décline toute
> responsabilité en cas d'usage abusif ou non autorisé.

## Informations

- **URL testée** : https://searching-murphy.com
- **Code HTTP** : 200
- **Test réalisé le 2026-10-12 11:01 UTC par Thomas Leroyer ([https://searching-murphy.com](https://searching-murphy.com))**
- **Score global** : **87 / 100**

## Détail des en-têtes

| En-tête | État | Points | Justification |
|---------|------|--------|---------------|
| Content-Security-Policy | faible | 12 | CSP présent mais 'unsafe-inline' sans nonce/hash affaiblit la protection. |
| Strict-Transport-Security | ok | 20 | HSTS présent avec max-age >= 180 jours. |
| X-Frame-Options | ok | 15 | X-Frame-Options DENY ou SAMEORIGIN : anti-clickjacking actif. |
| X-Content-Type-Options | ok | 15 | nosniff actif : le navigateur ne devine pas le type MIME. |
| Referrer-Policy | ok | 15 | Politique de referrer restrictive. |
| Permissions-Policy | ok | 10 | Permissions-Policy présent. |

## 3 priorités de correction

1. Content-Security-Policy : 13 point(s) perdus (faible). Voir references/headers-explained.md pour la configuration recommandée.

> AVERTISSEMENT LÉGAL : ce rapport est fourni à titre informatif uniquement.
> Il ne constitue ni un audit de sécurité complet, ni une garantie d'absence
> de vulnérabilité. L'outil n'effectue aucune action intrusive, aucune
> injection et aucune modification du site audité. L'usage de cet outil doit
> être limité aux sites dont vous êtes propriétaire ou pour lesquels vous
> disposez d'une autorisation explicite. L'auteur décline toute
> responsabilité en cas d'usage abusif ou non autorisé.