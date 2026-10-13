import os
import json
import time
from groq import Groq
from scan_parser import parse_nmap_text
from cve_search import search_cve_for_version
from prioritize import compute_priority

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

MODEL = "openai/gpt-oss-20b"

SYSTEM_PROMPT = (
    "Tu es un analyste sécurité. Réponds UNIQUEMENT à partir des résultats de "
    "l'outil search_cve. N'ajoute aucune CVE, date ou score CVSS qui n'apparaît "
    "pas dans ces résultats. Ne décris une CVE que par ce qui est écrit dans sa "
    "description, sans extrapoler ni ajouter de conséquence. Ne propose aucune "
    "action de configuration qui ne découle pas directement d'une description. "
    "N'indique aucun numéro de version cible : dis seulement de mettre à jour "
    "vers la dernière version stable. Les scores CVSS sont fournis par l'outil : "
    "affiche-les, ne dis jamais qu'ils manquent."
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


def call_tool(name: str, args: dict) -> str:
    if name == "search_cve":
        cves = search_cve_for_version(args["service"], args["version"])
        if not cves:
            return "Aucune CVE trouvée."
        cves = sorted(cves, key=lambda c: c.cvss_score, reverse=True)
        score, label = compute_priority(cves)
        summary = f"Priorité: {label} (CVSS max {score})\n"
        for c in cves[:5]:
            summary += f"- {c.cve_id} (CVSS {c.cvss_score}): {c.description[:300]}\n"
        return summary
    return "Outil inconnu."


def run_agent(raw_scan_text: str):
    findings = parse_nmap_text(raw_scan_text)
    findings_text = "\n".join(str(f) for f in findings)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Voici un rapport de scan réseau :\n{findings_text}\n\n"
                "Pour CHAQUE service, appelle search_cve avec le nom du logiciel et "
                "le numéro de version seul. Ensuite, réponds uniquement avec un "
                "tableau Markdown contenant TOUTES les CVE reçues, classées du plus "
                "urgent au moins urgent (CVSS décroissant), aux colonnes : "
                "Service | CVE | CVSS | Description (reformulée en 12 mots maximum, "
                "sans rien ajouter). Termine par une ligne unique : mettre à jour "
                "chaque service vers la dernière version stable."
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
            max_completion_tokens=4096,
            reasoning_effort="low",
        )
        choice = response.choices[0]
        message = choice.message

        # Pas de demande d'outil : l'IA a fini, on affiche sa réponse
        if not message.tool_calls:
            print("\n=== Recommandation finale ===")
            print(message.content)
            if choice.finish_reason == "length":
                print("\n[ATTENTION] Réponse tronquée : augmente max_completion_tokens.")
            return message.content

        # Sinon : on note sa demande, on exécute les outils, on renvoie les résultats
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
    sample_scan = """
    192.168.1.10 22 ssh OpenSSH 7.4
    192.168.1.10 80 http Apache 2.4.29
    """
    run_agent(sample_scan)