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
    def analysis_data(self):
        payload = "</script><script>window.pwned=1</script>&\u2028\u2029"
        return {
            "generated_at": "2026-10-09 10:00:00",
            "scan_seconds": 1,
            "system": {
                "os": "Windows",
                "build": "test",
                "arch": "x64",
                "user": payload,
                "home": "C:\\Users\\test",
                "filesystem": "NTFS",
                "disk_total": "100 GB",
                "disk_used": "50 GB",
                "disk_free": "50 GB",
            },
            "top5": [{
                "rank": 1,
                "tier": "green",
                "size": "1 GB",
                "type": "缓存",
                "name": payload,
                "path": payload,
                "note": "安全测试",
            }],
            "green": [{
                "name": payload,
                "path": payload,
                "size_estimate": "约 1 GB",
                "kill_processes": [],
                "commands": [{"label": payload, "cmd": "echo safe"}],
            }],
            "yellow": [{
                "name": "需要人工判断的测试项",
                "path": "C:\\test",
                "size_estimate": "1 GB",
                "content_profile": "测试数据",
                "why_manual": "测试",
                "disposal": "测试",
                "risk": "测试",
            }],
            "red": [{
                "name": "谨慎清理的测试项",
                "path": "C:\\test-app",
                "size_estimate": "1 GB",
                "why_keep": "测试",
                "indirect_release": "测试",
            }],
            "denied": ["C:\\denied"],
            "warnings": ["测试警告", {"path": "C:\\partial", "reason": "测试预算"}],
            "summary": {
                "overview": payload,
                "priority": [payload],
                "long_term": ["测试长期建议"],
                "tier_stats": {"green": "1 GB", "yellow": "1 GB", "red": "1 GB"},
            },
        }

    def write_analysis(self, path, data=None):
        path.write_text(
            json.dumps(data if data is not None else self.analysis_data(), ensure_ascii=False),
            encoding="utf-8",
        )

    def build(self, source, output):
        return subprocess.run(
            [sys.executable, str(BUILD), str(source), str(output)],
            capture_output=True,
            text=True,
        )

    def test_static_report_escapes_script_terminator(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "analysis.json", Path(directory) / "report.html"
            self.write_analysis(source)
            result = self.build(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = output.read_text(encoding="utf-8")
            self.assertNotIn("</script><script>window.pwned=1</script>", report)
            self.assertIn(r"\u003c/script\u003e\u003cscript\u003ewindow.pwned=1\u003c/script\u003e", report)
            self.assertIn(r"\u0026\u2028\u2029", report)

    def test_static_report_has_no_action_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "analysis.json", Path(directory) / "report.html"
            self.write_analysis(source)
            subprocess.run([sys.executable, str(BUILD), str(source), str(output)], check=True, capture_output=True, text=True)
            report = output.read_text(encoding="utf-8")
            for forbidden in ("/action", "fetch(", "server.py", "__DELETE_CONFIG__", "直接删除", "移到废纸篓"):
                self.assertNotIn(forbidden, report)

    def test_static_report_rejects_wrong_field_names(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "analysis.json", Path(directory) / "report.html"
            invalid = self.analysis_data()
            invalid["system"] = {"total": "100 GB", "used": "50 GB", "free": "50 GB"}
            self.write_analysis(source, invalid)
            result = self.build(source, output)
            self.assertEqual(result.returncode, 2)
            self.assertIn("分析报告输入无效", result.stderr)
            self.assertIn("system.os", result.stderr)
            self.assertFalse(output.exists())

    def test_static_report_rejects_mismatched_section_type(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "analysis.json", Path(directory) / "report.html"
            invalid = self.analysis_data()
            invalid["summary"] = "错误的摘要类型"
            self.write_analysis(source, invalid)
            result = self.build(source, output)
            self.assertEqual(result.returncode, 2)
            self.assertIn("summary 必须是对象", result.stderr)
            self.assertFalse(output.exists())


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
