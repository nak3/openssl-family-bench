#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "summarize_profiles.py"
SPEC = importlib.util.spec_from_file_location("summarize_profiles", SCRIPT_PATH)
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class SummarizeProfilesTest(unittest.TestCase):
    def write_profile(self, root, backend, value):
        stem = f"{backend}__x86_64__tls__TLS_AES_128_GCM_SHA256__transfer__1024"
        (root / f"{stem}.stat.csv").write_text(
            "1000,,cycles\n2000,,instructions\n", encoding="utf-8"
        )
        (root / f"{stem}.benchmark.jsonl").write_text(
            "\n".join([
                json.dumps({"mib_per_second": value - 1}),
                json.dumps({"mib_per_second": value + 1}),
            ]) + "\n",
            encoding="utf-8",
        )
        (root / f"{stem}.mode").write_text("hardware\n", encoding="utf-8")
        (root / f"{stem}.sampling").write_text("cpu-clock\n", encoding="utf-8")
        (root / f"{stem}.report.txt").write_text(
            " 60.0% tls13_record_recv\n", encoding="utf-8"
        )

    def test_renders_speed_comparison_and_collapsed_details(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_profile(root, "openssl", 150)
            self.write_profile(root, "libressl", 100)
            self.write_profile(root, "libressl-patched", 120)

            markdown = SUMMARY.render([root], "Test profiles")

        self.assertIn("## Performance comparison", markdown)
        self.assertIn("150.0 MiB/s", markdown)
        self.assertIn("100.0 MiB/s", markdown)
        self.assertIn("120.0 MiB/s", markdown)
        self.assertIn("**1.50×**", markdown)
        self.assertIn("**1.20×**", markdown)
        self.assertIn("### Quick comparison", markdown)
        self.assertIn("<summary><strong>OpenSSL</strong> — 1 case</summary>", markdown)
        self.assertIn("tls13_record_recv", markdown)


if __name__ == "__main__":
    unittest.main()
