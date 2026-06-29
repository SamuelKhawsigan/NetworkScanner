"""Checkpoint 10 tests: watch-mode dashboard controls + watch loop.

Run with: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from rich.console import Console

from wifi_scanner import main
from wifi_scanner.display.live_view import LiveDashboard
from wifi_scanner.scanner.models import Host


def cfg(**kw):
    base = dict(targets=["10.8.50.0/24"], filters={}, sort="ip", interval=2,
                output=None, no_live=True, watch=True, history_db=":memory:")
    base.update(kw)
    return SimpleNamespace(**base)


class TestDashboardWatchControls(unittest.TestCase):
    def test_begin_scan_resets_progress_and_counter(self):
        dash = LiveDashboard(cfg(), Console(width=120))
        dash.phase("Port scan", "ports", 10)
        dash.advance("ports", 5)
        dash.begin_scan(3)
        self.assertEqual(dash.scan_count, 3)
        self.assertEqual(dash._tasks, {})          # progress reset
        self.assertEqual(dash.status, "SCANNING")

    def test_set_status_shows_waiting_in_header(self):
        console = Console(width=120, record=True)
        dash = LiveDashboard(cfg(), console)
        dash.begin_scan(2)
        dash.set_status("WAITING 5s")
        console.print(dash._render())
        text = console.export_text()
        self.assertIn("WAITING 5s", text)
        self.assertIn("Scan #2", text)


class TestWatchWait(unittest.TestCase):
    def test_counts_down_and_sleeps(self):
        statuses = []
        dash = SimpleNamespace(set_status=lambda s: statuses.append(s))
        with mock.patch("time.sleep") as slept:
            main._watch_wait(dash, 3)
        self.assertEqual(statuses, ["WAITING 3s", "WAITING 2s", "WAITING 1s"])
        self.assertEqual(slept.call_count, 3)


class TestWatchLoop(unittest.TestCase):
    def test_loops_until_ctrl_c_then_final_report(self):
        passes = {"n": 0}

        def fake_pipeline(c, reporter, console):
            passes["n"] += 1
            if passes["n"] >= 3:
                raise KeyboardInterrupt
            return [Host(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01")], []

        with mock.patch.object(main, "_run_pipeline", side_effect=fake_pipeline), \
             mock.patch.object(main, "_record_history") as rec, \
             mock.patch.object(main, "_watch_wait") as wait, \
             mock.patch.object(main, "_print_final_report") as final, \
             mock.patch.object(main, "_write_exports") as exports:
            main.run_watch(cfg(), Console(quiet=True))

        self.assertEqual(passes["n"], 3)           # ran until the 3rd raised
        self.assertEqual(rec.call_count, 2)        # history recorded for 2 good passes
        self.assertEqual(wait.call_count, 2)
        final.assert_called_once()                 # final report on exit
        exports.assert_not_called()                # output is None

    def test_export_on_exit_when_requested(self):
        def fake_pipeline(c, reporter, console):
            raise KeyboardInterrupt

        # one good pass recorded before Ctrl+C so there are hosts to export
        seq = [([Host(ip="10.8.50.1", mac="aa:bb:cc:dd:ee:01")], [])]

        def pipeline(c, reporter, console):
            if seq:
                return seq.pop()
            raise KeyboardInterrupt

        with mock.patch.object(main, "_run_pipeline", side_effect=pipeline), \
             mock.patch.object(main, "_record_history"), \
             mock.patch.object(main, "_watch_wait"), \
             mock.patch.object(main, "_print_final_report"), \
             mock.patch.object(main, "_write_exports") as exports:
            main.run_watch(cfg(output="json"), Console(quiet=True))

        exports.assert_called_once()


if __name__ == "__main__":
    unittest.main()
