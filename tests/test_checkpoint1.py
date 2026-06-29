"""Checkpoint 1 tests: config integrity, CLI helpers, and command behavior.

Pure-logic and CLI-surface coverage only — no packets are sent. Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

import click
from click.testing import CliRunner

from wifi_scanner import config
from wifi_scanner.main import (
    ScanConfig,
    apply_mode_overrides,
    cli,
    count_hosts,
    parse_filters,
    parse_targets,
    resolve_ports,
)


def make_cfg(**overrides) -> ScanConfig:
    """Build a ScanConfig with sensible defaults, overriding select fields."""
    base = dict(
        targets=["10.8.50.0/23"], mode="full", ports_profile="common",
        ports=config.PORTS_COMMON, timeout=2, rate_pps=100, watch=False,
        interval=60, sort="ip", filters={}, output=None, out_file=None,
        no_ports=False, no_snmp=False, stealth=False, known_file=None,
        history_db="x.db", verbose=False, debug=False, dry_run=False,
    )
    base.update(overrides)
    return ScanConfig(**base)


class TestParseTargets(unittest.TestCase):
    def test_single_cidr_normalized(self):
        self.assertEqual(parse_targets("10.8.50.0/23"), ["10.8.50.0/23"])

    def test_host_normalized_to_network(self):
        # strict=False so a host address resolves to its /32
        self.assertEqual(parse_targets("10.8.50.5"), ["10.8.50.5/32"])

    def test_multi_target_comma_and_whitespace(self):
        self.assertEqual(
            parse_targets(" 10.8.50.0/24 , 10.8.51.0/24 "),
            ["10.8.50.0/24", "10.8.51.0/24"],
        )

    def test_invalid_raises_badparameter(self):
        with self.assertRaises(click.BadParameter):
            parse_targets("not-a-cidr")

    def test_empty_raises_badparameter(self):
        with self.assertRaises(click.BadParameter):
            parse_targets("   ")


class TestCountHosts(unittest.TestCase):
    def test_slash24_excludes_network_and_broadcast(self):
        self.assertEqual(count_hosts(["10.8.50.0/24"]), 254)

    def test_slash23(self):
        self.assertEqual(count_hosts(["10.8.50.0/23"]), 510)

    def test_multi_target_sums(self):
        self.assertEqual(count_hosts(["10.8.50.0/24", "10.8.51.0/24"]), 508)

    def test_single_host(self):
        self.assertEqual(count_hosts(["10.8.50.5/32"]), 1)


class TestParseFilters(unittest.TestCase):
    def test_none_is_empty(self):
        self.assertEqual(parse_filters(None), {})

    def test_single(self):
        self.assertEqual(parse_filters("type=printer"), {"type": "printer"})

    def test_multi_lowercases_key(self):
        self.assertEqual(
            parse_filters("Type=router,flags=NEW_DEVICE"),
            {"type": "router", "flags": "NEW_DEVICE"},
        )

    def test_missing_equals_raises(self):
        with self.assertRaises(click.BadParameter):
            parse_filters("typeprinter")


class TestResolvePorts(unittest.TestCase):
    def test_known_profiles_nonempty(self):
        for name in config.PORT_PROFILES:
            self.assertTrue(resolve_ports(name), f"{name} profile empty")

    def test_unknown_falls_back_to_common(self):
        self.assertEqual(resolve_ports("bogus"), config.PORTS_COMMON)


class TestModeOverrides(unittest.TestCase):
    def test_stealth_mode_slows_and_drops_snmp(self):
        cfg = apply_mode_overrides(make_cfg(mode="stealth"))
        self.assertEqual(cfg.rate_pps, config.STEALTH_RATE_PPS)
        self.assertTrue(cfg.no_snmp)

    def test_stealth_flag_independent_of_mode(self):
        cfg = apply_mode_overrides(make_cfg(stealth=True))
        self.assertEqual(cfg.rate_pps, config.STEALTH_RATE_PPS)
        self.assertTrue(cfg.no_snmp)

    def test_quick_skips_ports(self):
        self.assertTrue(apply_mode_overrides(make_cfg(mode="quick")).no_ports)

    def test_watch_mode_sets_watch(self):
        self.assertTrue(apply_mode_overrides(make_cfg(mode="watch")).watch)

    def test_full_mode_keeps_defaults(self):
        cfg = apply_mode_overrides(make_cfg(mode="full"))
        self.assertEqual(cfg.rate_pps, 100)
        self.assertFalse(cfg.no_ports)
        self.assertFalse(cfg.no_snmp)


class TestConfigIntegrity(unittest.TestCase):
    def test_confidence_labels_descending(self):
        thresholds = [t for t, _ in config.CONFIDENCE_LABELS]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))

    def test_confidence_label_boundaries(self):
        self.assertEqual(config.confidence_label(100), "CONFIRMED")
        self.assertEqual(config.confidence_label(90), "CONFIRMED")
        self.assertEqual(config.confidence_label(89), "HIGH")
        self.assertEqual(config.confidence_label(50), "MEDIUM")
        self.assertEqual(config.confidence_label(30), "LOW")
        self.assertEqual(config.confidence_label(0), "UNKNOWN")

    def test_port_risk_flags_reference_known_flags(self):
        for flag in config.PORT_RISK_FLAGS.values():
            self.assertIn(flag, config.RISK_FLAGS)

    def test_default_profile_exists(self):
        self.assertIn(config.DEFAULT_PORT_PROFILE, config.PORT_PROFILES)

    def test_default_mode_valid(self):
        self.assertIn(config.DEFAULT_MODE, config.MODES)

    def test_full_profile_is_superset_of_common(self):
        self.assertTrue(set(config.PORTS_COMMON).issubset(config.PORTS_FULL))


class TestCliSurface(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_help_exits_zero(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Office WiFi/LAN scanner", result.output)

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("0.1.0", result.output)

    def test_dry_run_renders_plan(self):
        result = self.runner.invoke(cli, ["--dry-run"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Scan Plan", result.output)
        self.assertIn("10.8.50.0/23", result.output)

    def test_bad_target_exit_2(self):
        result = self.runner.invoke(cli, ["--dry-run", "--target", "nope"])
        self.assertEqual(result.exit_code, 2)

    def test_invalid_mode_rejected(self):
        result = self.runner.invoke(cli, ["--mode", "turbo"])
        self.assertEqual(result.exit_code, 2)

    def test_dry_run_stealth_plan_shows_skipped_snmp(self):
        result = self.runner.invoke(cli, ["--dry-run", "--mode", "stealth"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("skipped", result.output)


if __name__ == "__main__":
    unittest.main()
