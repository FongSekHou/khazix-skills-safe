#!/usr/bin/env python3
"""Build a standalone, read-only storage analysis report.

Usage:
    build_report.py <analysis.json> [output.html]

Required input fields:
- generated_at: non-empty string
- scan_seconds: non-negative number
- system: object with os, build, arch, user, home, filesystem, disk_total,
  disk_used and disk_free

Optional sections must use the report template schema when supplied:
- top5: [{rank, tier, size, type, name, path, note}]
- green: [{name, path, size_estimate|size, kill_processes?, commands?}]
- yellow: [{name, path, size_estimate|size, content_profile, why_manual,
  disposal, risk}]
- red: [{name, path, size_estimate|size, why_keep, indirect_release}]
- denied: [path, ...]
- warnings: [message | {path, reason}, ...]
- summary: {overview, tier_stats:{green,yellow,red}, priority?, long_term?}

The generated HTML is self-contained: it has no local HTTP server, network
endpoint, or file operation capability.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")
SYSTEM_FIELDS = (
    "os", "build", "arch", "user", "home", "filesystem",
    "disk_total", "disk_used", "disk_free",
)
TOP5_FIELDS = ("rank", "tier", "size", "type", "name", "path", "note")
YELLOW_FIELDS = ("name", "path", "content_profile", "why_manual", "disposal", "risk")
RED_FIELDS = ("name", "path", "why_keep", "indirect_release")


def json_for_script(value):
    """Serialize JSON safely for an inline HTML script context.

    HTML parsers terminate a script element on ``</script>`` even when it is
    inside a JavaScript string. Escaping these characters prevents untrusted
    paths or analysis text from becoming executable markup.
    """
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def schema_error(path, message):
    raise ValueError("分析报告输入无效：%s %s" % (path, message))


def require_object(value, path):
    if not isinstance(value, dict):
        schema_error(path, "必须是对象")
    return value


def require_list(value, path):
    if not isinstance(value, list):
        schema_error(path, "必须是数组")
    return value


def require_text(value, path):
    if not isinstance(value, str) or not value.strip():
        schema_error(path, "必须是非空字符串")


def require_fields(item, path, fields):
    require_object(item, path)
    for field in fields:
        if field not in item:
            schema_error("%s.%s" % (path, field), "缺失")
        if field != "rank":
            require_text(item[field], "%s.%s" % (path, field))


def require_size(item, path):
    size = item.get("size", item.get("size_estimate"))
    require_text(size, "%s.size 或 %s.size_estimate" % (path, path))


def validate_rows(data, key, validator):
    if key not in data:
        return
    for index, item in enumerate(require_list(data[key], key)):
        validator(item, "%s[%d]" % (key, index))


def validate_top5(item, path):
    require_fields(item, path, TOP5_FIELDS)
    if not isinstance(item["rank"], int) or isinstance(item["rank"], bool):
        schema_error("%s.rank" % path, "必须是整数")
    if item["tier"] not in ("green", "yellow", "red"):
        schema_error("%s.tier" % path, "必须为 green、yellow 或 red")


def validate_green(item, path):
    require_fields(item, path, ("name", "path"))
    require_size(item, path)
    if "kill_processes" in item:
        for index, process in enumerate(require_list(item["kill_processes"], "%s.kill_processes" % path)):
            require_text(process, "%s.kill_processes[%d]" % (path, index))
    if "commands" in item:
        for index, command in enumerate(require_list(item["commands"], "%s.commands" % path)):
            require_fields(command, "%s.commands[%d]" % (path, index), ("label", "cmd"))


def validate_yellow(item, path):
    require_fields(item, path, YELLOW_FIELDS)
    require_size(item, path)


def validate_red(item, path):
    require_fields(item, path, RED_FIELDS)
    require_size(item, path)


def validate_summary(summary):
    require_object(summary, "summary")
    require_text(summary.get("overview"), "summary.overview")
    tiers = require_object(summary.get("tier_stats"), "summary.tier_stats")
    for tier in ("green", "yellow", "red"):
        require_text(tiers.get(tier), "summary.tier_stats.%s" % tier)
    if "priority" in summary:
        priority = summary["priority"]
        if isinstance(priority, str):
            require_text(priority, "summary.priority")
        else:
            for index, item in enumerate(require_list(priority, "summary.priority")):
                require_text(item, "summary.priority[%d]" % index)
    if "long_term" in summary:
        for index, item in enumerate(require_list(summary["long_term"], "summary.long_term")):
            require_text(item, "summary.long_term[%d]" % index)


def validate_analysis(data):
    """Reject incomplete data instead of emitting a misleading blank report."""
    require_object(data, "根对象")
    require_text(data.get("generated_at"), "generated_at")
    scan_seconds = data.get("scan_seconds")
    if (not isinstance(scan_seconds, (int, float)) or isinstance(scan_seconds, bool)
            or scan_seconds < 0):
        schema_error("scan_seconds", "必须是非负数字")

    system = require_object(data.get("system"), "system")
    for field in SYSTEM_FIELDS:
        require_text(system.get(field), "system.%s" % field)

    validate_rows(data, "top5", validate_top5)
    validate_rows(data, "green", validate_green)
    validate_rows(data, "yellow", validate_yellow)
    validate_rows(data, "red", validate_red)

    if "denied" in data:
        for index, path in enumerate(require_list(data["denied"], "denied")):
            require_text(path, "denied[%d]" % index)
    if "warnings" in data:
        for index, warning in enumerate(require_list(data["warnings"], "warnings")):
            if isinstance(warning, str):
                require_text(warning, "warnings[%d]" % index)
            else:
                warning = require_object(warning, "warnings[%d]" % index)
                require_text(warning.get("path"), "warnings[%d].path" % index)
                require_text(warning.get("reason"), "warnings[%d].reason" % index)
    if "summary" in data:
        validate_summary(data["summary"])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser(
        "~/Desktop/storage-report.html")

    try:
        with open(src, "r", encoding="utf-8") as f:
            data = json.load(f)
        validate_analysis(data)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print("错误: " + str(error), file=sys.stderr)
        sys.exit(2)

    with open(TEMPLATE, "r", encoding="utf-8") as f:
        template = f.read()

    html = template.replace("__REPORT_DATA__", json_for_script(data))
    if "__REPORT_DATA__" in html:
        raise RuntimeError("报告模板缺少数据占位符")

    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print("报告已生成（静态只读）: " + out)


if __name__ == "__main__":
    main()
