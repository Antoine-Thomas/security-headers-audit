# Avertissement légal — Security Headers Audit

Cet avertissement est inclus en tête et en pied de chaque rapport généré
par le script `audit-headers.py`. Il encadre l'usage de l'outil et la
portée des résultats.

---

## Texte de l'avertissement (tel qu'affiché dans les rapports)

> AVERTISSEMENT LEGAL : ce rapport est fourni à titre informatif uniquement.
> Il ne constitue ni un audit de sécurité complet, ni une garantie d'absence
> de vulnérabilité. L'outil n'effectue aucune action intrusive, aucune
> injection et aucune modification du site audité. L'usage de cet outil doit
> être limité aux sites dont vous êtes propriétaire ou pour lesquels vous
> disposez d'une autorisation explicite. L'auteur décline toute
> responsabilité en cas d'usage abusif ou non autorisé.

## Ce que couvre l'outil

- Vérification de **6 en-têtes HTTP de sécurité** (voir
  `headers-explained.md`).
- Un score indicatif /100 et des priorités de correction **suggestives**.
- Un **unique GET** : aucune requête agressive, aucun payload, aucun scan
  de vulnérabilités actif.

## Ce que l'outil ne couvre pas

- Il ne détecte pas les vulnérabilités applicatives (XSS exploitable,
  injections SQL, failles d'authentification...).
- Il n'évalue pas la sécurité du serveur, de l'application ou de
  l'hébergement.
- Il ne garantit pas l'absence de compromission.
- Il n'effectue **aucune correction** : les recommandations doivent être
  implémentées par un humain compétent, après validation.

## Usage responsable

- N'auditez que des sites **que vous possédez** ou pour lesquels vous avez
  une **autorisation écrite**.
- L'outil refuse par conception les adresses IP privées (127.0.0.1,
  192.168.*, 10.*, 172.16-31.*, ::1) et `localhost` afin de limiter les
  usages abusifs.
- La re-publication d'un rapport doit conserver cet avertissement et la
  mention de l'auteur.

## Responsabilité

L'auteur fournit cet outil « en l'état », sans garantie d'aucune sorte.
L'utilisateur est seul responsable de l'usage qu'il en fait et des
conséquences qui en découlent. Les recommandations sont génériques : leur
application à un site particulier doit être validée par un professionnel
de la sécurité.