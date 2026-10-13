import re
from dataclasses import dataclass
from typing import List


@dataclass
class ServiceFinding:
    host: str
    port: int
    service: str
    version: str

    def __repr__(self):
        return f"{self.service} {self.version} on {self.host}:{self.port}"
def parse_nmap_text(raw_text: str) -> List[ServiceFinding]:
    findings = []
    pattern = re.compile(r"(\S+)\s+(\d+)\s+(\S+)\s+(.+)")

    for line in raw_text.strip().splitlines():
        match = pattern.match(line.strip())
        if match:
            host, port, service, version = match.groups()
            findings.append(ServiceFinding(host, int(port), service, version.strip()))

    return findings
if __name__ == "__main__":
    sample = """
    192.168.1.10 22 ssh OpenSSH 8.2p1
    192.168.1.10 80 http Apache 2.4.41
    192.168.1.10 3306 mysql MySQL 5.7.30
    """
    results = parse_nmap_text(sample)
    for r in results:
        print(r)