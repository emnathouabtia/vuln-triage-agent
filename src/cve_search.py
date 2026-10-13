import re
import requests
from dataclasses import dataclass
from typing import List

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# nom du logiciel (en minuscules) -> (fournisseur, produit) tels que NVD les écrit
CPE_MAP = {
    "apache tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "nginx": ("f5", "nginx"),
    "redis": ("redis", "redis"),
    "proftpd": ("proftpd", "proftpd"),
    "samba": ("samba", "samba"),
    "php": ("php", "php"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "haproxy": ("haproxy", "haproxy"),
    "memcached": ("memcached", "memcached"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "bind": ("isc", "bind"),
}


@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss_score: float
    severity: str


def _query_nvd(url: str, params: dict) -> List[CVEResult]:
    try:
        response = requests.get(url, params=params, timeout=30)
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

        results.append(CVEResult(cve_id, desc_text[:400], score, severity))
    return results


def search_cve(service: str, version: str, max_results: int = 5) -> List[CVEResult]:
    """Recherche par mots-clés (garde-fou si le logiciel est inconnu)."""
    params = {"keywordSearch": f"{service} {version}", "resultsPerPage": max_results}
    return _query_nvd(NVD_API_URL, params)


def find_cpe_key(text: str):
    """Cherche le logiciel connu dans le texte (mots entiers, nom le plus long d'abord)."""
    text = text.lower()
    for key in sorted(CPE_MAP, key=len, reverse=True):
        if re.search(rf"\b{re.escape(key)}\b", text):
            return key
    return None


def search_cve_for_version(service: str, version: str, max_results: int = 200) -> List[CVEResult]:
    """Recherche exacte : seulement les CVE qui touchent cette version précise."""
    key = find_cpe_key(f"{service} {version}")
    number = re.search(r"\d+(?:\.\d+)+", version)

    if key is None or not number:
        print(f"[cve_search] '{service} {version}' inconnu, repli sur la recherche par mots-clés (moins précise)")
        return search_cve(service, version)

    vendor, product = CPE_MAP[key]
    cpe = f"cpe:2.3:a:{vendor}:{product}:{number.group(0)}:*:*:*:*:*:*:*"
    params = {"cpeName": cpe, "resultsPerPage": max_results}
    # "?isVulnerable" = ne garder que les CVE où ce logiciel est réellement touché
    return _query_nvd(f"{NVD_API_URL}?isVulnerable", params)


if __name__ == "__main__":
    for r in search_cve_for_version("ssh", "OpenSSH 7.4")[:10]:
        print(f"{r.cve_id} | CVSS {r.cvss_score} ({r.severity})")
