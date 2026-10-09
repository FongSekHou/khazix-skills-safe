#!/usr/bin/env python3
"""Build a standalone, read-only storage analysis report.

Usage:
    build_report.py <analysis.json> [output.html]

The input JSON is produced after interpreting scan.py output. The generated
HTML is self-contained: it has no local HTTP server, network endpoint, or file
operation capability.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")


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


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser(
        "~/Desktop/storage-report.html")

    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
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
