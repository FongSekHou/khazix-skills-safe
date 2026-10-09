import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
BUILD = SCRIPTS / "build_report.py"
SCAN = SCRIPTS / "scan.py"


def load_scan_module():
    spec = importlib.util.spec_from_file_location("storage_scan", SCAN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = load_scan_module()


class StaticReportSecurityTests(unittest.TestCase):
    def analysis(self, path):
        payload = "</script><script>window.pwned=1</script>&\u2028\u2029"
        path.write_text(json.dumps({
            "generated_at": "2026-10-09 10:00:00",
            "scan_seconds": 1,
            "system": {"os": "Windows", "build": "test", "arch": "x64", "user": payload, "home": "C:\\Users\\test", "filesystem": "NTFS", "disk_total": "100 GB", "disk_used": "50 GB", "disk_free": "50 GB"},
            "green": [{"name": payload, "path": payload, "size_estimate": "约 1 GB", "commands": [{"label": payload, "cmd": "echo safe"}]}],
            "summary": {"overview": payload, "priority": [payload], "tier_stats": {"green": "1 GB", "yellow": "0 GB", "red": "0 GB"}}
        }, ensure_ascii=False), encoding="utf-8")

    def test_static_report_escapes_script_terminator(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "analysis.json", Path(directory) / "report.html"
            self.analysis(source)
            result = subprocess.run([sys.executable, str(BUILD), str(source), str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = output.read_text(encoding="utf-8")
            self.assertNotIn("</script><script>window.pwned=1</script>", report)
            self.assertIn(r"\u003c/script\u003e\u003cscript\u003ewindow.pwned=1\u003c/script\u003e", report)
            self.assertIn(r"\u0026\u2028\u2029", report)

    def test_static_report_has_no_action_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "analysis.json", Path(directory) / "report.html"
            self.analysis(source)
            subprocess.run([sys.executable, str(BUILD), str(source), str(output)], check=True, capture_output=True, text=True)
            report = output.read_text(encoding="utf-8")
            for forbidden in ("/action", "fetch(", "server.py", "__DELETE_CONFIG__", "直接删除", "移到废纸篓"):
                self.assertNotIn(forbidden, report)


class ScanBoundaryTests(unittest.TestCase):
    def write_bytes(self, path, count):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * count)

    def test_windows_groups_count_each_path_once(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "profile"
            local = profile / "AppData" / "Local"
            roaming = profile / "AppData" / "Roaming"
            temp = local / "Temp"
            self.write_bytes(profile / "Documents" / "doc.bin", 30 * 1024)
            self.write_bytes(profile / "Downloads" / "installer.bin", 70 * 1024)
            self.write_bytes(profile / ".cache" / "cache.bin", 20 * 1024)
            self.write_bytes(temp / "temp.bin", 40 * 1024)
            self.write_bytes(local / "pip" / "Cache" / "pip.bin", 50 * 1024)
            self.write_bytes(roaming / "settings.bin", 60 * 1024)
            groups, denied, warnings = scan.scan_windows_paths(str(profile), str(local), str(roaming), str(temp), str(Path(directory) / "Program Files"), str(Path(directory) / "Program Files x86"), min_kb=0)
            counted = sum(item["size_kb"] for items in groups.values() for item in items)
            self.assertEqual(counted, 270)
            self.assertEqual(denied, [])
            self.assertEqual(warnings, [])

    def test_symlink_is_not_descended_or_counted_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            root, real, link = Path(directory) / "root", Path(directory) / "root" / "real", Path(directory) / "root" / "linked"
            self.write_bytes(real / "data.bin", 16 * 1024)
            try:
                os.symlink(real, link, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest("创建符号链接不可用：%s" % error)
            budget = scan.ScanBudget(max_entries=100, max_seconds=10)
            self.assertEqual(scan.dir_size_bytes(str(root), budget) // 1024, 16)
            self.assertTrue(any("reparse point" in item["reason"] for item in budget.warnings))

    def test_budget_marks_result_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            for index in range(5):
                self.write_bytes(root / ("file%d.bin" % index), 1024)
            budget = scan.ScanBudget(max_entries=2, max_seconds=10)
            rows, warnings = scan.scandir_children(str(root), min_kb=0, budget=budget)
            self.assertLess(len(rows), 5)
            self.assertTrue(warnings)
            self.assertIn("扫描上限", warnings[0]["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
