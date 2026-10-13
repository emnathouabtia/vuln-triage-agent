# Vuln Triage Agent

Agent IA de triage de vulnérabilités : il lit un scan réseau `nmap -sV`, interroge la base
officielle NVD et produit un rapport priorisé par gravité (CVSS), multi-hôtes.

Exemple de rapport généré : [docs/exemple_rapport.md](docs/exemple_rapport.md)

## Fonctionnement
1. `scan_parser.py` lit un scan `nmap -sV` (hôte, port, logiciel, version, plages de versions comprises).
2. `cve_search.py` interroge l'API NVD avec l'identifiant CPE exact du logiciel (23 logiciels
   reconnus), ce qui ne garde que les CVE qui touchent la version scannée.
3. `agent_llm.py` : un LLM (Groq, `openai/gpt-oss-20b`) appelle l'outil `search_cve` pour chaque
   logiciel. Le code impose la version exacte du scan, le LLM ne la choisit pas.
4. Le rapport est trié et construit par le code. Le LLM sert uniquement à traduire les descriptions
   en français.

## Choix de conception
- Anti-hallucination : le tri, les scores, les identifiants et les versions viennent des données,
  jamais du LLM.
- Recherche par CPE plutôt que par mots-clés : supprime les faux positifs de type « avant la version X ».
- Filtre des CVE propres à une distribution (Red Hat, SUSE, installeurs Windows).
- Résistance aux pannes réseau : nouvelles tentatives, et rapport quand même produit si l'API LLM
  est injoignable.

## Installation
    pip install groq requests
    setx GROQ_API_KEY "votre_cle"

## Utilisation
    nmap -sV -oN scan.txt <cible autorisée>
    cd src
    python agent_llm.py ..\scan.txt --top 10 --output ..\rapport.md

Options : `scan` (fichier de scan), `--top` (CVE les plus graves par logiciel, défaut 5),
`--output` (fichier du rapport).

## Limites
- Dictionnaire CPE limité à 23 logiciels (logiciel inconnu : repli sur une recherche par mots-clés, moins précise).
- La traduction peut coller deux mots ; cela ne concerne ni les CVE, ni les scores, ni le tri.
- Les CVE sont des failles possibles pour une version donnée : elles ne prouvent pas qu'une
  configuration est exploitable. À n'utiliser que sur des machines que vous avez le droit de scanner.

## Tests
    pip install pytest
    python -m pytest -q

Les tests (parser nmap, reconnaissance des logiciels) tournent hors ligne, sans clé API.
