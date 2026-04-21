import os
import tempfile
import unittest

import evidence_protector


class TestGhostProtocolOffline(unittest.TestCase):
    def _write_temp_log(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".log", text=True)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_build_baseline_smoke(self) -> None:
        path = self._write_temp_log(
            "2024-01-15T14:00:00Z aaaa\n"
            "2024-01-15T14:00:01Z aaaa\n"
            "2024-01-15T14:00:02Z aaaa\n"
        )
        try:
            baseline = evidence_protector.build_baseline(
                path, config=evidence_protector.GhostConfig(max_lines=100)
            )
            self.assertEqual(baseline.total_lines, 3)
            self.assertEqual(baseline.timestamps_found, 3)
            self.assertEqual(len(baseline.char_prob), 257)
            self.assertGreaterEqual(baseline.entropy_mean, 0.0)
        finally:
            os.remove(path)

    def test_analyze_detects_time_reversal(self) -> None:
        path = self._write_temp_log(
            "2024-01-15T14:00:10Z ok\n"
            "2024-01-15T14:00:05Z backwards\n"
        )
        try:
            report = evidence_protector.analyze_log(
                path,
                config=evidence_protector.GhostConfig(
                    max_lines=100,
                    window_lines=2,
                    gap_threshold_seconds=1,
                ),
            )
            kinds = [e.signal_type for e in report.events]
            self.assertIn("TIME_REVERSAL", kinds)
        finally:
            os.remove(path)

    def test_analyze_detects_injection_primitive_null_byte(self) -> None:
        # Note: write an actual NUL byte into the file.
        fd, path = tempfile.mkstemp(suffix=".log", text=False)
        os.close(fd)
        try:
            with open(path, "wb") as f:
                f.write(b"2024-01-15T14:00:00Z ok\n")
                f.write(b"2024-01-15T14:00:01Z bad\x00stuff\n")

            report = evidence_protector.analyze_log(
                path,
                config=evidence_protector.GhostConfig(max_lines=100, window_lines=2),
            )
            kinds = [e.signal_type for e in report.events]
            self.assertIn("INJECTION_PRIMITIVE", kinds)
        finally:
            os.remove(path)

    def test_analyze_with_baseline_detects_log_dna_shift(self) -> None:
        baseline_path = self._write_temp_log(
            "\n".join(
                [
                    f"2024-01-15T14:00:{i:02d}Z aaaaaaa" for i in range(40)
                ]
            )
            + "\n"
        )
        analyze_path = self._write_temp_log(
            "\n".join(
                [
                    f"2024-01-15T14:10:{i:02d}Z aaaaaaa" for i in range(10)
                ]
                + [
                    f"2024-01-15T14:11:{i:02d}Z ZZZZZZZZZZZZZZZZZZZ" for i in range(10)
                ]
            )
            + "\n"
        )
        try:
            baseline = evidence_protector.build_baseline(
                baseline_path, config=evidence_protector.GhostConfig(max_lines=10_000)
            )
            report = evidence_protector.analyze_log(
                analyze_path,
                baseline=baseline,
                config=evidence_protector.GhostConfig(
                    max_lines=10_000,
                    window_lines=10,
                    dna_jsd_threshold=0.02,
                    dna_min_window_chars=50,
                ),
            )
            kinds = [e.signal_type for e in report.events]
            self.assertIn("LOG_DNA_SHIFT", kinds)
        finally:
            os.remove(baseline_path)
            os.remove(analyze_path)


if __name__ == "__main__":
    unittest.main()
