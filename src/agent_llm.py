import os
import re
import json
import time
from datetime import datetime
from groq import Groq
from scan_parser import parse_nmap_text
from cve_search import search_cve_for_version
from prioritize import compute_priority

client = Groq(api_key=os.environ.get("GROQ_API_KEY"), timeout=60.0, max_retries=3)

MODEL = "openai/gpt-oss-20b"
TOP_N = 5  # nombre de CVE gardées par logiciel (les plus graves)

SYSTEM_PROMPT = (
    "Tu es un analyste sécurité. Utilise l'outil search_cve pour chaque logiciel "
    "de la liste. N'ajoute aucune information qui ne vient pas de l'outil."
)

TRANSLATE_PROMPT = (
    "Traduis chaque description de vulnérabilité en français, fidèlement, en une "
    "phrase. N'ajoute rien, ne supprime rien, n'interprète pas, mais corrige les "
    "mots collés par une espace manquante. Réponds uniquement avec une ligne par "
    "CVE au format : CVE-ID | traduction"
)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_cve",
            "description": "Cherche les CVE connues pour un logiciel et une version donnés.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Nom du logiciel, ex: 'OpenSSH', 'Apache httpd'"},
                    "version": {"type": "string", "description": "Numéro de version seul, ex: '7.4'"},
                },
                "required": ["service", "version"],
            },
        },
    }
]

# Résultats collectés pendant les appels d'outil : (service, hôtes, CVEResult)
ALL_RESULTS = []
# Services du scan : (produit, version, "hôte:port")
SERVICES = []

# CVE propres à une distribution : faux positifs pour un serveur Debian/Ubuntu
DISTRO_NOISE = ("red hat enterprise linux", "rhel", "suse", "oracle linux", "windows installer")

SCAN_SOURCE = "exemple intégré"


def safe_create(**kwargs):
    """Appel Groq avec nouvelles tentatives ; renvoie None si l'API reste injoignable."""
    for attempt in range(3):
        try:
            return client.chat.completions.create(**kwargs)
        except Exception as e:
            print(f"[agent] Appel Groq échoué ({type(e).__name__}), tentative {attempt + 1}/3")
            time.sleep(5 * (attempt + 1))
    return None


def clean(text: str) -> str:
    """Normalise les espaces et retours à la ligne."""
    return " ".join(text.split())


def short_desc(text: str, limit: int = 400) -> str:
    """Premières phrases de la description (jusqu'à ~120 caractères), tronquées."""
    sentences = re.split(r"(?<=[.!?])\s", clean(text))
    out = ""
    for s in sentences:
        if out and len(out) + len(s) > limit:
            break
        out = (out + " " + s).strip()
        if len(out) >= 120:
            break
    return out[:limit]


def hosts_for(service: str, version: str) -> str:
    """Liste des hôtes:ports du scan qui exécutent ce logiciel et cette version."""
    s = service.lower()
    found = []
    for product, ver, where in SERVICES:
        p = product.lower()
        if product == service and ver == version and where not in found:
            found.append(where)
    return ", ".join(found) if found else "-"


def resolve(service: str, version: str):
    """Retrouve le logiciel du scan correspondant à l'appel du LLM (version exacte du scan)."""
    s = service.lower()
    for product, ver, _ in SERVICES:
        p = product.lower()
        if (s in p or p in s) and (ver.startswith(version) or version.startswith(ver)):
            return product, ver
    return service, version


def call_tool(name: str, args: dict) -> str:
    if name == "search_cve":
        service, version = resolve(args["service"], args["version"])
        if (service, version) != (args["service"], args["version"]):
            print(f"[agent] version corrigée d'après le scan : {service} {version}")
        cves = search_cve_for_version(service, version)
        before = len(cves)
        cves = [c for c in cves if not any(k in c.description.lower() for k in DISTRO_NOISE)]
        if before != len(cves):
            print(f"[agent] {before - len(cves)} CVE spécifique(s) à une distribution ignorée(s)")
        if not cves:
            return "Aucune CVE trouvée."
        cves = sorted(cves, key=lambda c: c.cvss_score, reverse=True)
        score, label = compute_priority(cves)
        where = hosts_for(service, version)
        summary = f"Priorité: {label} (CVSS max {score})\n"
        for c in cves[:TOP_N]:
            ALL_RESULTS.append((service, where, c))
            summary += f"- {c.cve_id} (CVSS {c.cvss_score}): {clean(c.description)[:300]}\n"
        return summary
    return "Outil inconnu."


def translate(rows) -> dict:
    """Traduit les descriptions en français ; renvoie {cve_id: traduction}."""
    unique = {}
    for _, _, c in rows:
        unique.setdefault(c.cve_id, c)
    lines = "\n".join(f"{cid} | {short_desc(c.description)}" for cid, c in unique.items())
    try:
        r = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": TRANSLATE_PROMPT},
                {"role": "user", "content": lines},
            ],
            max_completion_tokens=6000,
            reasoning_effort="low",
        )
        out = r.choices[0].message.content or ""
    except Exception as e:
        print(f"[agent] Traduction impossible : {e}")
        return {}
    result = {}
    for line in out.splitlines():
        if "|" in line:
            cid, txt = line.split("|", 1)
            result[cid.strip().strip("*- ")] = txt.strip()
    return result


def print_report():
    if not ALL_RESULTS:
        print("Aucune CVE trouvée.")
        return
    rows = sorted(ALL_RESULTS, key=lambda r: r[2].cvss_score, reverse=True)
    fr = translate(rows)
    nb_hosts = len({w.split(":")[0] for _, _, w in SERVICES})

    lines = [
        "# Rapport de triage des vulnérabilités",
        "",
        f"- Date : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"- Source du scan : {SCAN_SOURCE} ({nb_hosts} hôte(s))",
        f"- Tri : CVSS décroissant (calculé par le code), {TOP_N} CVE les plus graves par logiciel",
        "",
        "| Logiciel | Hôtes | CVE | CVSS | Description |",
        "|---|---|---|---|---|",
    ]
    for service, where, c in rows:
        desc = fr.get(c.cve_id) or short_desc(c.description)
        desc = desc.replace("|", "/")
        lines.append(f"| {service} | {where} | {c.cve_id} | {c.cvss_score} | {desc} |")
    lines += ["", "Action : mettre à jour chaque logiciel vers la dernière version stable."]
    report = "\n".join(lines)

    print("\n=== Rapport final (trié par CVSS décroissant) ===")
    print(report)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rapport.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    print(f"\n[agent] rapport enregistré : {os.path.normpath(out_path)}")


def run_agent(raw_scan_text: str):
    findings = parse_nmap_text(raw_scan_text)
    if not findings:
        print("Aucun service avec version détectée dans le scan.")
        return
    ALL_RESULTS.clear()
    SERVICES.clear()
    for f in findings:
        SERVICES.append((f.product, f.version, f"{f.host}:{f.port}"))

    # Un seul appel par logiciel+version, même s'il tourne sur plusieurs machines
    unique = []
    for product, version, _ in SERVICES:
        if (product, version) not in unique:
            unique.append((product, version))
    software_list = "\n".join(f"- {p}, version {v}" for p, v in unique)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Logiciels détectés par le scan :\n{software_list}\n\n"
                "Pour CHAQUE logiciel de cette liste, appelle search_cve avec le nom "
                "du logiciel et le numéro de version seul. Quand tous les appels sont "
                "faits, réponds uniquement : OK."
            ),
        },
    ]

    max_turns = 12  # garde-fou contre une boucle infinie
    for turn in range(max_turns):
        response = safe_create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_completion_tokens=2048,
            reasoning_effort="low",
        )
        if response is None:
            print("[agent] API Groq injoignable : rapport construit avec les CVE déjà collectées")
            print_report()
            return
        message = response.choices[0].message

        # Plus d'appel d'outil : le code construit le rapport lui-même
        if not message.tool_calls:
            print_report()
            return

        messages.append({
            "role": "assistant",
            "content": message.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in message.tool_calls
            ],
        })

        for tc in message.tool_calls:
            args = json.loads(tc.function.arguments)
            print(f"[Tour {turn + 1}] Appel outil : {tc.function.name}({args})")
            result = call_tool(tc.function.name, args)
            print("Résultat brut de l'outil :\n", result)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            time.sleep(6)  # respecte la limite de NVD

    print("Nombre maximum de tours atteint sans réponse finale.")


if __name__ == "__main__":
    scan_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scan.txt")
    if os.path.exists(scan_path):
        with open(scan_path, encoding="utf-8-sig", errors="ignore") as f:
            scan_text = f.read()
        SCAN_SOURCE = "scan.txt"
        print(f"[agent] scan lu depuis {os.path.normpath(scan_path)}")
    else:
        print("[agent] scan.txt introuvable, utilisation de l'exemple")
        scan_text = """
        192.168.1.10 22 ssh OpenSSH 7.4
        192.168.1.10 80 http Apache 2.4.29
        """
    run_agent(scan_text)


