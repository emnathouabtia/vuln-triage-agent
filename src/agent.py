import time
from scan_parser import parse_nmap_text
from cve_search import search_cve
from prioritize import prioritize_findings


def run_pipeline(raw_scan_text: str, delay_between_calls: float = 6.0):
    print("1/3 — Parsing du rapport de scan...")
    findings = parse_nmap_text(raw_scan_text)
    print(f"   → {len(findings)} services détectés")

    print("2/3 — Recherche des CVE...")
    cve_map = {}
    for finding in findings:
        cves = search_cve(finding.service, finding.version)
        cve_map[repr(finding)] = cves
        print(f"   → {finding.service} {finding.version}: {len(cves)} CVE(s)")
        time.sleep(delay_between_calls)  # respecte le rate limit NVD

    print("3/3 — Priorisation...")
    results = prioritize_findings(findings, cve_map)
    return results


if __name__ == "__main__":
    sample_scan = """
    192.168.1.10 22 ssh OpenSSH 7.4
    192.168.1.10 80 http Apache 2.4.29
    """
    results = run_pipeline(sample_scan)
    print("\n=== RÉSULTATS ===")
    for r in results:
        print(r)