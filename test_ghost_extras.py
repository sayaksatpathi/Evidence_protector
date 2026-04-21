import json
import os
import tempfile
import unittest

import evidence_protector

from evidence_protector.ghost_canary import (
    generate_canary,
    load_canary,
    save_canary,
    scan_for_canary,
)
from evidence_protector.ghost_commitments import append_commitment, verify_commitments, append_witness, verify_witnesses
from evidence_protector.ghost_correlate import correlate_report_with_receipts, load_receipts_jsonl
from evidence_protector.ghost_receipts import collect_receipts, write_receipts_jsonl


class TestGhostExtras(unittest.TestCase):
    def _write_temp_log(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".log", text=True)
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_commit_register_append_and_verify(self) -> None:
        log_path = self._write_temp_log("2024-01-15T14:00:00Z ok\n")
        fd, reg_path = tempfile.mkstemp(suffix=".jsonl", text=True)
        os.close(fd)
        try:
            # start clean
            with open(reg_path, "w", encoding="utf-8") as f:
                f.write("")

            entry = append_commitment(file_path=log_path, register_path=reg_path, note="unit-test")
            self.assertTrue(entry.entry_hash)

            ok, reason = verify_commitments(reg_path)
            self.assertTrue(ok, reason)
        finally:
            os.remove(log_path)
            os.remove(reg_path)

    def test_canary_generate_save_load_and_scan(self) -> None:
        log_path = self._write_temp_log("hello\n")
        fd, canary_path = tempfile.mkstemp(suffix=".canary.json", text=True)
        os.close(fd)
        try:
            canary = generate_canary(hint="test")
            save_canary(canary, canary_path)
            loaded = load_canary(canary_path)
            self.assertEqual(loaded.token, canary.token)

            # plant the canary
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"TOKEN={canary.token}\n")

            matches = scan_for_canary(log_path, loaded.token)
            self.assertTrue(matches)
        finally:
            os.remove(log_path)
            os.remove(canary_path)

    def test_receipts_collect_and_correlate(self) -> None:
        # Start with a larger file, then rewrite smaller to reliably trigger truncation.
        log_path = self._write_temp_log(
            "2024-01-15T14:00:00Z ok\n" + "2024-01-15T14:00:01Z ok\n" + ("X" * 512) + "\n"
        )
        fd, receipts_path = tempfile.mkstemp(suffix=".jsonl", text=True)
        os.close(fd)
        try:
            with open(receipts_path, "w", encoding="utf-8") as f:
                f.write("")

            r1 = collect_receipts(file_path=log_path, include_samples=True)
            write_receipts_jsonl(r1, receipts_path, append=True)

            # truncate file to force size decrease
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("2024-01-15T14:00:00Z ok\n")

            r2 = collect_receipts(file_path=log_path, include_samples=True)
            write_receipts_jsonl(r2, receipts_path, append=True)

            report = evidence_protector.analyze_log(log_path)
            receipts = load_receipts_jsonl(receipts_path)
            correlated = correlate_report_with_receipts(report, receipts)
            kinds = [e.signal_type for e in correlated.events]
            # Depending on file system timestamps, truncation is the stable one.
            self.assertIn("FS_TRUNCATION", kinds)
        finally:
            os.remove(log_path)
            os.remove(receipts_path)

    def test_anchor_witness_append_and_verify(self) -> None:
        log_path = self._write_temp_log("2024-01-15T14:00:00Z ok\n")
        fd, reg_path = tempfile.mkstemp(suffix=".jsonl", text=True)
        os.close(fd)
        fd2, witness_path = tempfile.mkstemp(suffix=".witness.jsonl", text=True)
        os.close(fd2)
        try:
            with open(reg_path, "w", encoding="utf-8") as f:
                f.write("")
            with open(witness_path, "w", encoding="utf-8") as f:
                f.write("")

            append_commitment(file_path=log_path, register_path=reg_path, note="unit-test")
            append_witness(register_path=reg_path, witness_log_path=witness_path, channel="unit-test", note="hi")

            ok, reason = verify_witnesses(reg_path, witness_path)
            self.assertTrue(ok, reason)
        finally:
            os.remove(log_path)
            os.remove(reg_path)
            os.remove(witness_path)


if __name__ == "__main__":
    unittest.main()
