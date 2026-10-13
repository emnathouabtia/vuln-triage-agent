# Rapport de triage des vulnérabilités

- Date : 2026-10-14 01:31
- Source du scan : scan.txt (2 hôte(s))
- Tri : CVSS décroissant (calculé par le code), 3 CVE les plus graves par logiciel

| Logiciel | Hôtes | CVE | CVSS | Description |
|---|---|---|---|---|
| Redis key-value store | 192.168.1.20:6379 | CVE-2025-49844 | 9.9 | Redis est une base de données open source en mémoire qui persiste sur disque. Les versions 8.2.1 et antérieures permettent à un utilisateur authentifié d’utiliser un script Lua spécialement conçu pour manipuler le ramasse-miettes, déclencher un use‑after‑free et potentiellement conduire à une exécution de code à distance. |
| OpenSSH | 192.168.1.10:22, 192.168.1.20:22 | CVE-2023-38408 | 9.8 | La fonction PKCS#11 dans ssh‑agent d’OpenSSH avant 9.3p2 possède un chemin de recherche insuffisamment fiable, ce qui conduit à une exécution de code à distance si un agent est transféré vers un système contrôlé par un attaquant. |
| Apache httpd | 192.168.1.10:80 | CVE-2018-1312 | 9.8 | Dans Apache httpd 2.2.0 à 2.4.29, lors de la génération d'un défi d'authentification HTTP Digest, le nonce envoyé pour empêcher les attaques de réponse n'était pas correctement généré à l'aide d'un graine pseudo‑aléatoire. |
| Apache httpd | 192.168.1.10:80 | CVE-2021-26691 | 9.8 | Dans les versions 2.4.0 à 2.4.46 du serveur HTTP Apache, un SessionHeader spécialement conçu envoyé par un serveur d'origine peut provoquer un débordement de tas. |
| Apache httpd | 192.168.1.10:80 | CVE-2021-39275 | 9.8 | la fonction ap_escape_quotes() peut écrire au-delà de la fin d'un tampon lorsqu'on lui fournit une entrée malveillante. Aucun module inclus ne passe des données non fiables à ces fonctions, mais des modules tiers/externes le peuvent. |
| PostgreSQL DB | 192.168.1.10:5432 | CVE-2018-1115 | 9.1 | PostgreSQL avant les versions 10.4 et 9.6.9 est vulnérable dans l'extension adminpack, la fonction pg_catalog.pg_logfile_rotate() ne suit pas les mêmes ACL que pg_rorate_logfile. |
| PostgreSQL DB | 192.168.1.10:5432 | CVE-2018-1058 | 8.8 | Un défaut a été trouvé dans la façon dont PostgreSQL permettait à un utilisateur de modifier le comportement d'une requête pour d'autres utilisateurs. Un attaquant disposant d'un compte utilisateur peut utiliser ce défaut pour exécuter du code avec les permissions de superutilisateur dans la base de données. |
| PostgreSQL DB | 192.168.1.10:5432 | CVE-2019-10208 | 8.8 | Un défaut a été découvert dans les versions 9.4.x avant 9.4.24, 9.5.x avant 9.5.19, 9.6.x avant 9.6.15, 10.x avant 10.10 et 11.x avant 11.5 de PostgreSQL où des instructions SQL arbitraires peuvent être exécutées avec une fonction SECURITY DEFINER appropriée. |
| Redis key-value store | 192.168.1.20:6379 | CVE-2026-25243 | 8.8 | Redis est un magasin de structures de données en mémoire. Dans les versions de redis‑server jusqu'à 8.6.3, la commande RESTORE ne valide pas correctement les valeurs sérialisées. |
| Redis key-value store | 192.168.1.20:6379 | CVE-2026-23631 | 8.1 | Redis est un magasin de structures de données en mémoire. Dans toutes les versions de redis‑server avec le script Lua, un attaquant authentifié peut exploiter le mécanisme de synchronisation maître‑réplica pour déclencher un use‑after‑free sur les réplicas où replica‑read‑only est désactivé ou peut être désactivé, ce qui peut conduire à une exécution de code à distance. |
| OpenSSH | 192.168.1.10:22, 192.168.1.20:22 | CVE-2026-60002 | 7.7 | ssh dans OpenSSH avant 10.4 peut présenter un use‑after‑free lorsqu'un serveur change sa clé d'hôte lors d'un rééchange de clés. (Cette issue ne se produit que du côté client.) |
| OpenSSH | 192.168.1.10:22, 192.168.1.20:22 | CVE-2026-35385 | 7.5 | Dans OpenSSH avant 10.3, un fichier téléchargé par scp peut être installé avec les bits setuid ou setgid, un résultat contraire aux attentes de certains utilisateurs, si le téléchargement est effectué en tant que root avec -O (protocole scp hérité) et sans -p (préserver les modes). |

Action : mettre à jour chaque logiciel vers la dernière version stable.
