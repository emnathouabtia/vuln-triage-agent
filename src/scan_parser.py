import re
from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    host: str
    port: int
    service: str
    product: str
    version: str

    def __str__(self) -> str:
        return f"Hôte {self.host} | port {self.port} ({self.service}) : {self.product} {self.version}"


NMAP_PORT_RE = re.compile(r"^(\d+)/(?:tcp|udp)\s+open\s+(\S+)\s*(.*)$")
SIMPLE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)\s+(.+)$")
HOST_RE = re.compile(r"^Nmap scan report for (?:\S+ \()?([^)\s]+)\)?")
VERSION_RE = re.compile(r"\d+(?:\.\d+)+(?:p\d+)?")


def _split_product_version(text: str):
    match = VERSION_RE.search(text)
    if not match:
        return text.strip(), ""
    return text[: match.start()].strip(), match.group(0)


def parse_nmap_text(raw_text: str) -> List[Finding]:
    findings: List[Finding] = []
    host = "inconnu"

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = HOST_RE.match(line)
        if m:
            host = m.group(1)
            continue

        m = NMAP_PORT_RE.match(line)
        if m:
            port, service, rest = int(m.group(1)), m.group(2), m.group(3)
        else:
            m = SIMPLE_RE.match(line)
            if not m:
                continue
            host, port, service, rest = m.group(1), int(m.group(2)), m.group(3), m.group(4)

        product, version = _split_product_version(rest)
        if not product or not version:
            print(f"[scan_parser] port {port} ({service}) ignoré : version non détectée")
            continue

        findings.append(Finding(host, port, service, product, version))

    return findings


if __name__ == "__main__":
    test = """
    Nmap scan report for localhost (127.0.0.1)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.4p1 Debian 10 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    192.168.1.10 3306 mysql MySQL 5.7.30
    """
    for f in parse_nmap_text(test):
        print(f)


# Alias pour compatibilité avec prioritize.py
ServiceFinding = Finding
