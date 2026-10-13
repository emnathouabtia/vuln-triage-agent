import os
import re
import json
import time
from datetime import datetime
from groq import Groq
from scan_parser import parse_nmap_text
from cve_search import search_cve_for_version
from prioritize import compute_priority

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

MODEL = "openai/gpt-oss-20b"

SYSTEM_PROMPT = (
    "Tu es un analyste sécurité. Utilise l'outil search_cve pour chaque service "
    "du scan. N'ajoute aucune information qui ne vient pas de l'outil."
)

TRANSLATE_PROMPT = (
    "Traduis chaque description de vulnérabilité en français, fidèlement, en une "
    "phrase. N'ajoute rien, ne supprime rien, n'interprète pas, mais corrige les mots collés par une espace manquante. Réponds "
    "uniquement avec une ligne par CVE au format : CVE-ID | traduction"
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
                    "service": {"type": "string", "description": "Nom du logiciel, ex: 'OpenSSH', 'Apache'"},
                    "version": {"type": "string", "description": "Numéro de version seul, ex: '7.4'"},
                },
                "required": ["service", "version"],
            },
        },
    }
]

# Résultats collectés pendant les appels d'outil : (service, CVEResult)
ALL_RESULTS = []

# CVE propres à une distribution : faux positifs pour un serveur Debian/Ubuntu
DISTRO_NOISE = ("red hat enterprise linux", "rhel", "suse", "oracle linux")

SCAN_SOURCE = "exemple intégré"


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


def call_tool(name: str, args: dict) -> str:
    if name == "search_cve":
        cves = search_cve_for_version(args["service"], args["version"])
        before = len(cves)
        cves = [c for c in cves if not any(k in c.description.lower() for k in DISTRO_NOISE)]
        if before != len(cves):
            print(f"[agent] {before - len(cves)} CVE spécifique(s) à une distribution ignorée(s)")
        if not cves:
            return "Aucune CVE trouvée."
        cves = sorted(cves, key=lambda c: c.cvss_score, reverse=True)
        score, label = compute_priority(cves)
        summary = f"Priorité: {label} (CVSS max {score})\n"
        for c in cves[:10]:
            ALL_RESULTS.append((args["service"], c))
            summary += f"- {c.cve_id} (CVSS {c.cvss_score}): {clean(c.description)[:300]}\n"
        return summary
    return "Outil inconnu."


def translate(rows) -> dict:
    """Traduit les descriptions en français ; renvoie {cve_id: traduction}."""
    lines = "\n".join(f"{c.cve_id} | {short_desc(c.description)}" for _, c in rows)
    try:
        r = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": TRANSLATE_PROMPT},
                {"role": "user", "content": lines},
            ],
            max_completion_tokens=4000,
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
    rows = sorted(ALL_RESULTS, key=lambda r: r[1].cvss_score, reverse=True)
    fr = translate(rows)

    lines = [
        "# Rapport de triage des vulnérabilités",
        "",
        f"- Date : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"- Source du scan : {SCAN_SOURCE}",
        "- Tri : CVSS décroissant (calculé par le code)",
        "",
        "| Service | CVE | CVSS | Description |",
        "|---|---|---|---|",
    ]
    for service, c in rows:
        desc = fr.get(c.cve_id) or short_desc(c.description)
        desc = desc.replace("|", "/")
        lines.append(f"| {service} | {c.cve_id} | {c.cvss_score} | {desc} |")
    lines += ["", "Action : mettre à jour chaque service vers la dernière version stable."]
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
    findings_text = "\n".join(str(f) for f in findings)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Voici un rapport de scan réseau :\n{findings_text}\n\n"
                "Pour CHAQUE service, appelle search_cve avec le nom du logiciel et "
                "le numéro de version seul. Quand tous les appels sont faits, "
                "réponds uniquement : OK."
            ),
        },
    ]

    max_turns = 10  # garde-fou contre une boucle infinie
    for turn in range(max_turns):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_completion_tokens=2048,
            reasoning_effort="low",
        )
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

