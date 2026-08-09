"""
Unit tests for DomainSentinel's parsing and risk-analysis engine.

These tests mock the underlying `whois.whois()` call so they run
anywhere without needing live WHOIS/network access.

Run with:
    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import domainsentinel as ds  # noqa: E402


class FakeWhois:
    """Minimal stand-in for python-whois's WhoisEntry object."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getattr__(self, name):
        return None

    text = "Domain Name: FAKE.COM\n"


class TestNormalizeDomain(unittest.TestCase):

    def test_strips_scheme_and_path(self):
        self.assertEqual(ds.normalize_domain("https://Example.com/path"), "example.com")

    def test_strips_www(self):
        self.assertEqual(ds.normalize_domain("www.Example.COM"), "example.com")


class TestParsing(unittest.TestCase):

    def test_first_handles_list_and_scalar(self):
        self.assertEqual(ds._first(["a", "b"]), "a")
        self.assertEqual(ds._first("a"), "a")
        self.assertIsNone(ds._first(None))
        self.assertIsNone(ds._first([]))

    def test_as_list_dedupes_nothing_but_wraps_scalars(self):
        self.assertEqual(ds._as_list("ns1.example.com"), ["ns1.example.com"])
        self.assertEqual(ds._as_list(None), [])
        self.assertEqual(ds._as_list(["a", "b"]), ["a", "b"])

    def test_as_datetime_normalizes_tz_aware(self):
        aware = datetime.now(timezone.utc)
        naive = ds._as_datetime(aware)
        self.assertIsNone(naive.tzinfo)

    def test_as_datetime_parses_string(self):
        result = ds._as_datetime("2020-01-15 00:00:00")
        self.assertEqual(result.year, 2020)

    def test_parse_whois_result_maps_fields(self):
        fake = FakeWhois(domain_name="EXAMPLE.COM", registrar="Test Registrar",
                          name_servers=["ns1.example.com", "ns2.example.com"], status=["ok"])
        record = ds.parse_whois_result(fake)
        self.assertEqual(record.domain_name, "EXAMPLE.COM")
        self.assertEqual(record.registrar, "Test Registrar")
        self.assertEqual(sorted(record.name_servers), ["ns1.example.com", "ns2.example.com"])


class TestRiskAnalysis(unittest.TestCase):

    def test_expired_domain_is_critical(self):
        record = ds.DomainRecord(expiration_date=datetime.now() - timedelta(days=5))
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "Expired Domain" and r.severity == "CRITICAL" for r in risks))

    def test_expiring_soon_is_high(self):
        record = ds.DomainRecord(expiration_date=datetime.now() + timedelta(days=15))
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "Expiring Soon" and r.severity == "HIGH" for r in risks))

    def test_newly_registered_is_high(self):
        record = ds.DomainRecord(creation_date=datetime.now() - timedelta(days=5))
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "Newly Registered Domain" and r.severity == "HIGH" for r in risks))

    def test_hold_status_is_critical(self):
        record = ds.DomainRecord(status=["clientHold"])
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "Domain On Hold" and r.severity == "CRITICAL" for r in risks))

    def test_pending_delete_is_critical(self):
        record = ds.DomainRecord(status=["pendingDelete"])
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "Domain Pending Deletion" for r in risks))

    def test_no_name_servers_is_critical(self):
        record = ds.DomainRecord(name_servers=[])
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "No Name Servers" and r.severity == "CRITICAL" for r in risks))

    def test_privacy_registrar_flagged_info(self):
        record = ds.DomainRecord(registrar="WhoisGuard Protected", name_servers=["ns1.x.com"])
        risks = ds.analyze_risk(record)
        self.assertTrue(any(r.factor == "Privacy Protection Enabled" and r.severity == "INFO" for r in risks))

    def test_healthy_domain_has_minimal_risk(self):
        record = ds.DomainRecord(
            creation_date=datetime.now() - timedelta(days=3650),
            expiration_date=datetime.now() + timedelta(days=200),
            name_servers=["ns1.example.com"],
            status=["ok"],
            dnssec="signed",
            registrant_name="Jane Doe",
            registrar_abuse_contact="abuse@example.com",
        )
        risks = ds.analyze_risk(record)
        self.assertEqual(len([r for r in risks if r.severity in ("CRITICAL", "HIGH")]), 0)


class TestScanDomainWithMockedWhois(unittest.TestCase):

    def test_scan_domain_success(self):
        fake = FakeWhois(
            domain_name="EXAMPLE.COM", registrar="Test Registrar",
            creation_date=datetime.now() - timedelta(days=1000),
            expiration_date=datetime.now() + timedelta(days=100),
            name_servers=["ns1.example.com"], status=["ok"], dnssec="signed",
        )
        with patch.object(ds.whois, "whois", return_value=fake):
            result = ds.scan_domain("example.com", timeout=5, resolve=False)
        self.assertIsNone(result.error)
        self.assertEqual(result.record.registrar, "Test Registrar")

    def test_scan_domain_failure(self):
        with patch.object(ds.whois, "whois", side_effect=Exception("no match")):
            result = ds.scan_domain("nonexistent.test", timeout=5, resolve=False)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.worst_severity, "ERROR")


if __name__ == "__main__":
    unittest.main()
