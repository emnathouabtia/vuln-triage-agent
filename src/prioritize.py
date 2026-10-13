from dataclasses import dataclass
from typing import List
from cve_search import CVEResult
from scan_parser import ServiceFinding


@dataclass
class PrioritizedFinding:
    service_finding: ServiceFinding
    cves: List[CVEResult]
    priority_score: float
    priority_label: str

    def __repr__(self):
        return (
            f"[{self.priority_label}] {self.service_finding} "
            f"— {len(self.cves)} CVE(s), score max {self.priority_score}"
        )


def compute_priority(cves: List[CVEResult]) -> tuple:
    if not cves:
        return 0.0, "AUCUNE_CVE_TROUVEE"

    max_score = max(c.cvss_score for c in cves)

    if max_score >= 9.0:
        label = "CRITIQUE"
    elif max_score >= 7.0:
        label = "HAUTE"
    elif max_score >= 4.0:
        label = "MOYENNE"
    else:
        label = "FAIBLE"

    return max_score, label


def prioritize_findings(service_findings: List[ServiceFinding], cve_map: dict) -> List[PrioritizedFinding]:
    prioritized = []
    for finding in service_findings:
        cves = cve_map.get(repr(finding), [])
        score, label = compute_priority(cves)
        prioritized.append(PrioritizedFinding(finding, cves, score, label))

    prioritized.sort(key=lambda x: x.priority_score, reverse=True)
    return prioritized