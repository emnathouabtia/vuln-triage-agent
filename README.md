# Vuln Triage Agent

Agent IA de triage de vulnérabilités : il lit un scan réseau nmap, interroge la base NVD
et produit un rapport priorisé par gravité (CVSS).

## Fonctionnement
1. `scan_parser.py` lit un scan `nmap -sV` (service + version).
2. `cve_search.py` interroge l'API NVD avec l'identifiant exact du logiciel (CPE) pour ne garder
   que les CVE qui touchent la version scannée.
3. `agent_llm.py` : un LLM (Groq, `openai/gpt-oss-20b`) appelle l'outil `search_cve` pour chaque service.
4. Le rapport est trié par le code (pas par le LLM) ; le LLM sert uniquement à traduire les
   descriptions en français, fidèlement.

## Choix de conception
- Anti-hallucination : le tri, les scores et les identifiants viennent des données NVD, jamais du LLM.
- Recherche par CPE plutôt que par mots-clés : supprime les faux positifs de type « avant la version X ».

## Utilisation
```powershell
pip install groq requests
setx GROQ_API_KEY "votre_cle"
nmap -sV -oN scan.txt <cible autorisée>
cd src
python agent_llm.py
```

## Limites
- Dictionnaire CPE limité (OpenSSH, Apache, MySQL, nginx).
- Certains faux positifs restent possibles (ex. CVE spécifiques à une distribution).
