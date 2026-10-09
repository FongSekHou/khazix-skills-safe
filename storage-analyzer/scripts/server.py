#!/usr/bin/env python3
"""Deprecated compatibility stub for storage-analyzer-safe.

This fork intentionally has no local HTTP server and no file-operation API.
Use build_report.py to create a standalone, read-only report instead.
"""
import sys


def main():
    print("server.py 已停用：storage-analyzer-safe 仅生成静态只读报告。", file=sys.stderr)
    print("请改用：python scripts/build_report.py <analysis.json> [output.html]", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
