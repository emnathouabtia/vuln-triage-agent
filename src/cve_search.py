import re
import requests
from dataclasses import dataclass
from typing import List

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# nom du service -> (fournisseur, produit) tels que NVD les écrit
CPE_MAP = {
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "mysql": ("oracle", "mysql"),
    "nginx": ("f5", "nginx"),
}


@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss_score: float
    severity: str


def _query_nvd(url: str, params: dict) -> List[CVEResult]:
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"[cve_search] Erreur API : {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score, severity = 0.0, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                entry = metrics[key][0]
                score = entry["cvssData"].get("baseScore", 0.0)
                severity = entry["cvssData"].get("baseSeverity") or entry.get("baseSeverity", "UNKNOWN")
                break

        results.append(CVEResult(cve_id, desc_text[:200], score, severity))
    return results


def search_cve(service: str, version: str, max_results: int = 5) -> List[CVEResult]:
    """Ancienne recherche par mots-clés (garde-fou si le service est inconnu)."""
    params = {"keywordSearch": f"{service} {version}", "resultsPerPage": max_results}
    return _query_nvd(NVD_API_URL, params)

def search_cve_for_version(service: str, version: str, max_results: int = 200) -> List[CVEResult]:
    """Recherche exacte : seulement les CVE qui touchent cette version précise."""
    text = f"{service} {version}".lower()
    key = next((k for k in CPE_MAP if k in text), None)
    number = re.search(r"\d+(?:\.\d+)+", version)

    if key is None or not number:
        print(f"[cve_search] '{service} {version}' inconnu, repli sur la recherche par mots-clés")
        return search_cve(service, version)

    vendor, product = CPE_MAP[key]
    cpe = f"cpe:2.3:a:{vendor}:{product}:{number.group(0)}:*:*:*:*:*:*:*"
    params = {"cpeName": cpe, "resultsPerPage": max_results}
    return _query_nvd(f"{NVD_API_URL}?isVulnerable", params)


if __name__ == "__main__":
    for r in search_cve_for_version("OpenSSH", "7.4"):
        print(f"{r.cve_id} | CVSS {r.cvss_score} ({r.severity})")
