from scan_parser import parse_nmap_text

SCAN = """
Nmap scan report for web01 (192.168.1.10)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.29 ((Ubuntu))
5432/tcp open  postgresql PostgreSQL DB 9.6.0 - 9.6.5

Nmap scan report for db01 (192.168.1.20)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10 (protocol 2.0)
6379/tcp open  redis   Redis key-value store 5.0.7
"""


def by_key(findings):
    return {(f.host, f.port): f for f in findings}


def test_multi_host_scan_assigns_hosts_and_ports():
    findings = parse_nmap_text(SCAN)
    assert [(f.host, f.port) for f in findings] == [
        ("192.168.1.10", 22),
        ("192.168.1.10", 80),
        ("192.168.1.10", 5432),
        ("192.168.1.20", 22),
        ("192.168.1.20", 6379),
    ]


def test_product_and_version_are_split():
    f = by_key(parse_nmap_text(SCAN))
    ssh = f[("192.168.1.10", 22)]
    assert (ssh.product, ssh.version) == ("OpenSSH", "7.4p1")
    apache = f[("192.168.1.10", 80)]
    assert (apache.product, apache.version) == ("Apache httpd", "2.4.29")
    redis = f[("192.168.1.20", 6379)]
    assert (redis.product, redis.version) == ("Redis key-value store", "5.0.7")


def test_version_range_keeps_upper_bound():
    f = by_key(parse_nmap_text(SCAN))
    pg = f[("192.168.1.10", 5432)]
    assert pg.version == "9.6.5"


def test_simple_format_is_supported():
    findings = parse_nmap_text("192.168.1.10 3306 mysql MySQL 5.7.30")
    assert len(findings) == 1
    f = findings[0]
    assert (f.host, f.port, f.service) == ("192.168.1.10", 3306, "mysql")
    assert (f.product, f.version) == ("MySQL", "5.7.30")


def test_closed_and_versionless_ports_are_ignored():
    text = """
Nmap scan report for host (10.0.0.5)
23/tcp closed telnet
443/tcp open https
25/tcp open smtp Postfix smtpd
"""
    assert parse_nmap_text(text) == []


def test_empty_text_gives_no_findings():
    assert parse_nmap_text("") == []
