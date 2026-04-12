import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st

import evidence_protector
from evidence_protector import (
    extract_timestamp,
    scan_log,
    format_duration,
)


class TestExtractTimestamp(unittest.TestCase):
    def test_iso8601_timestamp(self) -> None:
        line = "2024-01-15T14:23:01Z INFO Start"
        ts = extract_timestamp(line)
        self.assertIsNotNone(ts)
        assert ts is not None
        self.assertEqual(ts.year, 2024)
        self.assertEqual(ts.month, 1)
        self.assertEqual(ts.day, 15)
        self.assertEqual(ts.hour, 14)
        self.assertEqual(ts.minute, 23)
        self.assertEqual(ts.second, 1)
        self.assertIsNotNone(ts.tzinfo)

    def test_apache_timestamp(self) -> None:
        line = "[15/Jan/2024:14:23:01 +0000] GET /index.html"
        ts = extract_timestamp(line)
        self.assertIsNotNone(ts)
        assert ts is not None
        self.assertEqual(ts.year, 2024)
        self.assertEqual(ts.month, 1)
        self.assertEqual(ts.day, 15)
        self.assertEqual(ts.hour, 14)
        self.assertEqual(ts.minute, 23)
        self.assertEqual(ts.second, 1)
        self.assertIsNotNone(ts.tzinfo)

    def test_apache_errorlog_timestamp(self) -> None:
        line = "[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok"
        ts = extract_timestamp(line)
        self.assertIsNotNone(ts)
        assert ts is not None
        self.assertEqual(ts.year, 2005)
        self.assertEqual(ts.month, 12)
        self.assertEqual(ts.day, 4)
        self.assertEqual(ts.hour, 4)
        self.assertEqual(ts.minute, 47)
        self.assertEqual(ts.second, 44)
        self.assertIsNotNone(ts.tzinfo)

    def test_syslog_timestamp(self) -> None:
        line = "Jan 15 14:23:01 host process[1]: message"
        ts = extract_timestamp(line)
        self.assertIsNotNone(ts)
        assert ts is not None
        current_year = datetime.now(timezone.utc).year
        self.assertEqual(ts.year, current_year)
        self.assertEqual(ts.month, 1)
        self.assertEqual(ts.day, 15)
        self.assertEqual(ts.hour, 14)
        self.assertEqual(ts.minute, 23)
        self.assertEqual(ts.second, 1)
        self.assertIsNotNone(ts.tzinfo)

    def test_no_timestamp_returns_none(self) -> None:
        line = "this line has no timestamp"
        ts = extract_timestamp(line)
        self.assertIsNone(ts)


class TestFormatDuration(unittest.TestCase):
    def test_zero_seconds(self) -> None:
        self.assertEqual(format_duration(0), "0s")

    def test_only_seconds(self) -> None:
        self.assertEqual(format_duration(59), "59s")

    def test_minutes_and_seconds(self) -> None:
        self.assertEqual(format_duration(65), "1m 5s")

    def test_hours_minutes_seconds(self) -> None:
        self.assertEqual(format_duration(3665), "1h 1m 5s")

    def test_negative_seconds(self) -> None:
        self.assertEqual(format_duration(-3665), "1h 1m 5s")


class TestFingerprintPhrase(unittest.TestCase):
    def test_fingerprint_phrase_from_hex_bytes(self) -> None:
        # Bytes: 00 01 02 03
        # adjective1 = adjectives[0] -> absurd
        # adjective2 = adjectives[(1 + 3) % n] -> adjectives[4] -> bitten
        # noun1      = nouns[2] -> atlas
        # suffix     = 0x0001
        self.assertEqual(evidence_protector.fingerprint_phrase("00010203"), "absurd-bitten-atlas-0001")


class TestScanLog(unittest.TestCase):
    def _write_temp_log(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".log", text=True)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_scan_log_detects_gap_and_anomaly(self) -> None:
        # Construct a small log with a normal gap and a timestamp anomaly
        lines = [
            "2024-01-15T14:23:01Z first\n",
            "2024-01-15T14:24:01Z second\n",  # 60s later
            "2024-01-15T14:35:01Z big gap ends\n",  # 11 min gap -> suspicious for threshold 300
            "2024-01-15T14:34:01Z anomaly backwards\n",  # goes back 1 minute -> TIMESTAMP_ANOMALY
        ]
        log_content = "".join(lines)
        path = self._write_temp_log(log_content)
        try:
            gaps, stats = scan_log(path, gap_threshold=300)

            # Expect two gaps: one large gap, one anomaly
            self.assertEqual(len(gaps), 2)
            self.assertEqual(stats["gaps_found"], 2)

            # First gap: between line 2 and 3
            gap1 = gaps[0]
            self.assertEqual(gap1.line_start, 2)
            self.assertEqual(gap1.line_end, 3)
            self.assertIsNone(gap1.note)
            self.assertGreater(gap1.duration_seconds, 300)

            # Second gap: anomaly between line 3 and 4
            gap2 = gaps[1]
            self.assertEqual(gap2.line_start, 3)
            self.assertEqual(gap2.line_end, 4)
            self.assertEqual(gap2.note, "TIMESTAMP_ANOMALY")
            self.assertGreater(gap2.duration_seconds, 0)

        finally:
            os.remove(path)

    def test_scan_log_counts_malformed_lines(self) -> None:
        lines = [
            "no timestamp here\n",
            "2024-01-15T14:23:01Z valid\n",
            "broken line again\n",
            "2024-01-15T14:24:01Z valid again\n",
        ]
        log_content = "".join(lines)
        path = self._write_temp_log(log_content)
        try:
            gaps, stats = scan_log(path, gap_threshold=300)
            self.assertEqual(stats["total_lines"], 4)
            self.assertEqual(stats["malformed_lines"], 2)
            self.assertEqual(stats["timestamps_found"], 2)
            # No gap above threshold
            self.assertEqual(len(gaps), 0)
        finally:
            os.remove(path)


class TestExtractTimestampFuzz(unittest.TestCase):

    @given(st.text())
    @settings(max_examples=500)
    def test_never_crashes_on_arbitrary_input(self, line):
        """extract_timestamp must never raise — only return datetime or None."""

        result = extract_timestamp(line)
        assert result is None or hasattr(result, "tzinfo")

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                whitelist_characters=":-/[] +TZ",
            )
        )
    )
    @settings(max_examples=300)
    def test_datetime_result_is_always_utc(self, line):
        """Any returned datetime must be timezone-aware UTC."""

        result = extract_timestamp(line)
        if result is not None:
            from datetime import timezone

            assert result.tzinfo == timezone.utc


class TestReporters(unittest.TestCase):
    def _sample_stats(self, file: str = "sample.log", threshold: int = 300) -> dict:
        return {
            "file": file,
            "threshold_seconds": threshold,
            "total_lines": 10,
            "malformed_lines": 2,
            "gaps_found": 0,
            "timestamps_found": 8,
        }

    def _sample_gaps(self) -> list:
        # One normal gap, one anomaly, and one > 1h gap to cover duration styling.
        return [
            evidence_protector.SuspiciousGap(
                gap_index=1,
                gap_start=datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc),
                gap_end=datetime(2024, 1, 15, 14, 10, 0, tzinfo=timezone.utc),
                duration_seconds=600,
                line_start=10,
                line_end=20,
                note=None,
            ),
            evidence_protector.SuspiciousGap(
                gap_index=2,
                gap_start=datetime(2024, 1, 15, 15, 0, 0, tzinfo=timezone.utc),
                gap_end=datetime(2024, 1, 15, 13, 59, 0, tzinfo=timezone.utc),
                duration_seconds=3661,
                line_start=21,
                line_end=22,
                note="TIMESTAMP_ANOMALY",
            ),
        ]

    def test_report_terminal_no_gaps_prints_message(self) -> None:
        buf = io.StringIO()
        old_console = evidence_protector.console
        try:
            evidence_protector.console = evidence_protector.Console(
                file=buf, no_color=True, force_terminal=False
            )
            args = type("Args", (), {"out": None})()
            stats = self._sample_stats()
            evidence_protector.report_terminal([], stats, args)
        finally:
            evidence_protector.console = old_console

        text = buf.getvalue()
        self.assertIn("Evidence Protector Report", text)
        self.assertIn("No suspicious gaps found.", text)

    def test_report_terminal_writes_plain_text_file(self) -> None:
        gaps = self._sample_gaps()
        stats = self._sample_stats(file="temp.log")
        stats["gaps_found"] = len(gaps)

        fd, out_path = tempfile.mkstemp(suffix=".txt", text=True)
        os.close(fd)
        try:
            # Avoid writing the rich table to the real terminal during the test.
            old_console = evidence_protector.console
            evidence_protector.console = evidence_protector.Console(
                file=io.StringIO(), no_color=True, force_terminal=False
            )
            args = type("Args", (), {"out": out_path})()
            evidence_protector.report_terminal(gaps, stats, args)

            evidence_protector.console = old_console

            with open(out_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Evidence Protector Report", content)
            # Rich may truncate long cell content based on console width.
            self.assertIn("TIMESTAMP", content)
        finally:
            evidence_protector.console = old_console
            os.remove(out_path)

    def test_report_csv_writes_rows(self) -> None:
        gaps = self._sample_gaps()
        fd, out_path = tempfile.mkstemp(suffix=".csv", text=True)
        os.close(fd)
        try:
            args = type("Args", (), {"out": out_path})()
            evidence_protector.report_csv(gaps, {}, args)

            with open(out_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("gap_index,gap_start,gap_end", content)
            self.assertIn("TIMESTAMP_ANOMALY", content)
        finally:
            os.remove(out_path)

    def test_report_json_stdout_and_file(self) -> None:
        gaps = self._sample_gaps()
        stats = self._sample_stats(file="sample.log")
        stats["gaps_found"] = len(gaps)

        # stdout
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            args = type("Args", (), {"out": None})()
            evidence_protector.report_json(gaps, stats, args)
        data = json.loads(out_buf.getvalue())
        self.assertEqual(data["file"], "sample.log")
        self.assertEqual(len(data["suspicious_gaps"]), len(gaps))

        # file
        fd, out_path = tempfile.mkstemp(suffix=".json", text=True)
        os.close(fd)
        try:
            args = type("Args", (), {"out": out_path})()
            evidence_protector.report_json(gaps, stats, args)
            with open(out_path, "r", encoding="utf-8") as f:
                file_data = json.load(f)
            self.assertEqual(file_data["gaps_found"], len(gaps))
        finally:
            os.remove(out_path)


class TestMainCallback(unittest.TestCase):
    def _write_temp_log(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".log", text=True)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_main_callback_warns_when_no_timestamps(self) -> None:
        path = self._write_temp_log("hello world\nno timestamps here\n")
        try:
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                evidence_protector.main.callback(
                    file=path,
                    gap=300,
                    output_format="terminal",
                    out=None,
                    manifest=None,
                    mode="scan",
                )
            self.assertIn("Warning: no parseable timestamps found", err_buf.getvalue())
        finally:
            os.remove(path)

    def test_main_callback_csv_and_json_paths(self) -> None:
        path = self._write_temp_log(
            "2024-01-15T14:23:01Z first\n2024-01-15T14:35:01Z second\n"
        )
        fd_csv, out_csv = tempfile.mkstemp(suffix=".csv", text=True)
        os.close(fd_csv)
        fd_json, out_json = tempfile.mkstemp(suffix=".json", text=True)
        os.close(fd_json)
        try:
            evidence_protector.main.callback(
                file=path,
                gap=300,
                output_format="csv",
                out=out_csv,
                manifest=None,
                mode="scan",
            )
            evidence_protector.main.callback(
                file=path,
                gap=300,
                output_format="json",
                out=out_json,
                manifest=None,
                mode="scan",
            )

            with open(out_csv, "r", encoding="utf-8") as f:
                self.assertIn("gap_index", f.read())
            with open(out_json, "r", encoding="utf-8") as f:
                self.assertIn("suspicious_gaps", f.read())
        finally:
            os.remove(path)
            os.remove(out_csv)
            os.remove(out_json)

    def test_main_callback_verify_uses_manifest_and_writes_report(self) -> None:
        path = self._write_temp_log("2024-01-15T14:23:01Z first\n")

        fd_manifest, manifest_path = tempfile.mkstemp(suffix=".manifest.json", text=True)
        os.close(fd_manifest)
        fd_report, report_path = tempfile.mkstemp(suffix=".json", text=True)
        os.close(fd_report)

        old_console = evidence_protector.console
        evidence_protector.console = evidence_protector.Console(file=io.StringIO(), no_color=True)
        try:
            evidence_protector.sign_log(path, manifest_path)

            evidence_protector.main.callback(
                file=path,
                gap=300,
                output_format="terminal",
                out=report_path,
                manifest=manifest_path,
                mode="verify",
            )

            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertTrue(data["clean"])
            self.assertEqual(data["manifest"], manifest_path)
        finally:
            evidence_protector.console = old_console
            if os.path.exists(manifest_path):
                os.remove(manifest_path)
            os.remove(report_path)
            os.remove(path)


class TestHashChainIntegrity(unittest.TestCase):
    def _write_temp_log(self, lines: list[str]) -> str:
        fd, path = tempfile.mkstemp(suffix=".log", text=True)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
        return path

    def test_build_hash_chain_matches_algorithm(self) -> None:
        lines = ["alpha\n", "beta\n", "gamma\n"]
        path = self._write_temp_log(lines)
        try:
            chain = evidence_protector.build_hash_chain(path)
            self.assertEqual(len(chain), 3)

            prev = ""
            for idx, raw_line in enumerate(lines, start=1):
                expected_line_hash = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
                expected_chain_hash = hashlib.sha256((raw_line + prev).encode("utf-8")).hexdigest()
                self.assertEqual(chain[idx - 1].line_number, idx)
                self.assertEqual(chain[idx - 1].line_hash, expected_line_hash)
                self.assertEqual(chain[idx - 1].chain_hash, expected_chain_hash)
                prev = expected_chain_hash
        finally:
            os.remove(path)

    def test_sign_and_verify_clean(self) -> None:
        lines = [
            "2024-01-15T14:23:01Z first\n",
            "2024-01-15T14:35:01Z second\n",
        ]
        path = self._write_temp_log(lines)
        manifest_path = evidence_protector._default_manifest_path(path)

        old_console = evidence_protector.console
        evidence_protector.console = evidence_protector.Console(file=io.StringIO(), no_color=True)
        try:
            evidence_protector.sign_log(path, None)
            self.assertTrue(os.path.exists(manifest_path))

            # verify_log should not raise on clean file
            evidence_protector.verify_log(path, None, None)
        finally:
            evidence_protector.console = old_console
            if os.path.exists(manifest_path):
                os.remove(manifest_path)
            os.remove(path)

    def test_verify_detects_tampering_and_exits_2(self) -> None:
        lines = ["alpha\n", "beta\n", "gamma\n"]
        path = self._write_temp_log(lines)
        manifest_path = evidence_protector._default_manifest_path(path)

        old_console = evidence_protector.console
        evidence_protector.console = evidence_protector.Console(file=io.StringIO(), no_color=True)
        try:
            evidence_protector.sign_log(path, None)

            # Tamper with the file
            with open(path, "w", encoding="utf-8") as f:
                f.write("alpha\n")
                f.write("BETA_CHANGED\n")
                f.write("gamma\n")

            with self.assertRaises(SystemExit) as ctx:
                evidence_protector.verify_log(path, None, None)
            self.assertEqual(ctx.exception.code, 2)
        finally:
            evidence_protector.console = old_console
            if os.path.exists(manifest_path):
                os.remove(manifest_path)
            os.remove(path)

    def test_verify_writes_json_report_clean_and_tampered(self) -> None:
        lines = ["alpha\n", "beta\n", "gamma\n"]
        path = self._write_temp_log(lines)
        manifest_path = evidence_protector._default_manifest_path(path)

        fd_report, report_path = tempfile.mkstemp(suffix=".json", text=True)
        os.close(fd_report)

        old_console = evidence_protector.console
        evidence_protector.console = evidence_protector.Console(file=io.StringIO(), no_color=True)
        try:
            evidence_protector.sign_log(path, None)

            # Clean report
            evidence_protector.verify_log(path, None, report_path)
            with open(report_path, "r", encoding="utf-8") as f:
                clean_data = json.load(f)
            self.assertTrue(clean_data["clean"])
            self.assertEqual(clean_data["issues_found"], 0)
            self.assertEqual(clean_data["file"], path)
            self.assertEqual(clean_data["manifest"], manifest_path)

            # Tamper with the file and ensure a report is still written before exit.
            with open(path, "w", encoding="utf-8") as f:
                f.write("alpha\n")
                f.write("BETA_CHANGED\n")
                f.write("gamma\n")

            with self.assertRaises(SystemExit) as ctx:
                evidence_protector.verify_log(path, None, report_path)
            self.assertEqual(ctx.exception.code, 2)

            with open(report_path, "r", encoding="utf-8") as f:
                tampered_data = json.load(f)
            self.assertFalse(tampered_data["clean"])
            self.assertGreater(tampered_data["issues_found"], 0)
            statuses = {issue["status"] for issue in tampered_data["issues"]}
            self.assertIn("TAMPERED", statuses)
        finally:
            evidence_protector.console = old_console
            if os.path.exists(manifest_path):
                os.remove(manifest_path)
            if os.path.exists(report_path):
                os.remove(report_path)
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
