"""Tests for capture metadata extraction and peer comparison."""

import pytest

from app.analysis.metadata import CaptureMetadata, HostProfile, _median


class TestMedian:
    def test_odd_list(self):
        assert _median([1, 3, 5]) == 3

    def test_even_list(self):
        assert _median([1, 2, 3, 4]) == 2.5

    def test_single(self):
        assert _median([42]) == 42

    def test_empty(self):
        assert _median([]) == 0.0


class TestCaptureMetadata:
    def _make_meta(self) -> CaptureMetadata:
        meta = CaptureMetadata()
        meta.host_profiles["10.0.0.1"] = HostProfile(
            ip="10.0.0.1", is_internal=True,
            packet_count=100, bytes_outbound=10000, dns_query_count=50,
        )
        meta.host_profiles["10.0.0.2"] = HostProfile(
            ip="10.0.0.2", is_internal=True,
            packet_count=80, bytes_outbound=5000, dns_query_count=10,
        )
        meta.host_profiles["203.0.113.1"] = HostProfile(
            ip="203.0.113.1", is_internal=False,
            packet_count=60,
        )
        meta.median_bytes_per_host = 7500
        meta.median_dns_queries_per_host = 30
        meta.external_ip_to_internal_hosts["203.0.113.1"] = {"10.0.0.1"}
        return meta

    def test_external_fanin(self):
        meta = self._make_meta()
        assert meta.external_fanin("203.0.113.1") == 1
        meta.external_ip_to_internal_hosts["203.0.113.1"].add("10.0.0.2")
        assert meta.external_fanin("203.0.113.1") == 2

    def test_is_sole_contactor(self):
        meta = self._make_meta()
        assert meta.is_sole_contactor("10.0.0.1", "203.0.113.1") is True
        meta.external_ip_to_internal_hosts["203.0.113.1"].add("10.0.0.2")
        assert meta.is_sole_contactor("10.0.0.1", "203.0.113.1") is False

    def test_host_dns_ratio(self):
        meta = self._make_meta()
        # 10.0.0.1 has 50 queries, median is 30 → 1.67x
        ratio = meta.host_dns_ratio("10.0.0.1")
        assert abs(ratio - 50 / 30) < 0.01

    def test_host_bytes_ratio(self):
        meta = self._make_meta()
        # 10.0.0.1 has 10000 bytes, median is 7500 → 1.33x
        ratio = meta.host_bytes_ratio("10.0.0.1")
        assert abs(ratio - 10000 / 7500) < 0.01

    def test_unknown_host_defaults(self):
        meta = self._make_meta()
        assert meta.host_dns_ratio("192.168.99.99") == 1.0
        assert meta.host_bytes_ratio("192.168.99.99") == 1.0
        assert meta.external_fanin("1.2.3.4") == 0
