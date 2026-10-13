import pytest

from cve_search import CPE_MAP, find_cpe_key


@pytest.mark.parametrize(
    "text, expected",
    [
        ("ssh OpenSSH 7.4", "openssh"),
        ("Apache httpd 2.4.29", "apache httpd"),
        ("Apache Tomcat 9.0.30", "apache tomcat"),
        ("Redis key-value store 5.0.7", "redis"),
        ("PostgreSQL DB 9.6.5", "postgresql"),
        ("logiciel inconnu 1.2", None),
    ],
)
def test_find_cpe_key(text, expected):
    assert find_cpe_key(text) == expected


def test_longest_name_wins():
    # "apache tomcat" ne doit pas être pris pour "apache" (httpd)
    assert find_cpe_key("Apache Tomcat 9.0") == "apache tomcat"


def test_every_cpe_entry_is_a_vendor_product_pair():
    for name, pair in CPE_MAP.items():
        assert name == name.lower()
        assert len(pair) == 2 and all(pair)
