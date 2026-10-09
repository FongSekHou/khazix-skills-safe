#!/usr/bin/env python3
"""Bounded, read-only storage scanner for macOS and Windows.

The scanner only reads directory entries and metadata. It never creates,
changes, moves, or deletes files. Results may be partial when a permission,
reparse point, or resource budget prevents a complete traversal; those limits
are returned in ``denied`` and ``warnings`` rather than reported as zero bytes.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field

HOME = os.path.expanduser("~")
DEFAULT_MAX_ENTRIES = 120_000
DEFAULT_MAX_SECONDS = 90
DEFAULT_MAX_DEPTH = 40


def human(kb):
    """Render a KB value as a compact human-readable size."""
    value = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit not in ("B", "KB") else f"{int(value)} {unit}"
        value /= 1024


def canonical(path):
    return os.path.normcase(os.path.normpath(os.path.abspath(os.path.expanduser(path))))


def is_within(path, root):
    path, root = canonical(path), canonical(root)
    return path == root or path.startswith(root + os.sep)


def is_reparse_or_link(path, entry=None):
    """Return True for symlinks and Windows reparse points without following them."""
    try:
        info = entry.stat(follow_symlinks=False) if entry else os.lstat(path)
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(reparse and attributes & reparse)


@dataclass
class ScanBudget:
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_seconds: int = DEFAULT_MAX_SECONDS
    max_depth: int = DEFAULT_MAX_DEPTH
    started: float = field(default_factory=time.monotonic)
    entries: int = 0
    partial_reason: str = ""
    visited: set = field(default_factory=set)
    denied: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def consume(self, path, depth):
        if self.partial_reason:
            return False
        if depth > self.max_depth:
            self.partial_reason = "超过最大目录深度"
        elif self.entries >= self.max_entries:
            self.partial_reason = "超过目录项扫描上限"
        elif time.monotonic() - self.started >= self.max_seconds:
            self.partial_reason = "超过扫描时间上限"
        if self.partial_reason:
            self.warnings.append({"path": path, "reason": self.partial_reason})
            return False
        self.entries += 1
        return True

    def deny(self, path):
        if path not in self.denied:
            self.denied.append(path)

    def skip_reparse(self, path):
        self.warnings.append({"path": path, "reason": "已跳过符号链接或 Windows reparse point"})


def directory_identity(path):
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    # A zero inode does not provide a stable identity on some file systems.
    return (info.st_dev, info.st_ino) if info.st_ino else None


def dir_size_bytes(path, budget=None, exclude_roots=(), depth=0):
    """Bounded recursive byte count that never descends links/reparse points."""
    budget = budget or ScanBudget()
    if not budget.consume(path, depth):
        return 0
    if is_reparse_or_link(path):
        budget.skip_reparse(path)
        return 0
    if any(is_within(path, root) for root in exclude_roots):
        return 0
    identity = directory_identity(path)
    if identity and identity in budget.visited:
        budget.warnings.append({"path": path, "reason": "已跳过重复目录标识"})
        return 0
    if identity:
        budget.visited.add(identity)

    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if not budget.consume(entry.path, depth + 1):
                    break
                if any(is_within(entry.path, root) for root in exclude_roots):
                    continue
                try:
                    if is_reparse_or_link(entry.path, entry):
                        budget.skip_reparse(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        total += dir_size_bytes(entry.path, budget, exclude_roots, depth + 1)
                except (PermissionError, OSError):
                    budget.deny(entry.path)
    except (PermissionError, OSError):
        budget.deny(path)
    return total


def scandir_children(path, min_kb=51200, limit=40, exclude_roots=(), budget=None):
    """Measure immediate children, with bounded recursive measurement below each."""
    if not path or not os.path.isdir(path) or is_reparse_or_link(path):
        return [], []
    budget = budget or ScanBudget()
    results = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if not budget.consume(entry.path, 1):
                    break
                if any(is_within(entry.path, root) for root in exclude_roots):
                    continue
                try:
                    if is_reparse_or_link(entry.path, entry):
                        budget.skip_reparse(entry.path)
                        continue
                    if entry.is_file(follow_symlinks=False):
                        size = entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        size = dir_size_bytes(entry.path, budget, exclude_roots, 1)
                    else:
                        continue
                except (PermissionError, OSError):
                    budget.deny(entry.path)
                    continue
                kb = size // 1024
                if kb >= min_kb:
                    results.append({"name": entry.name, "path": entry.path, "size_kb": kb, "size_h": human(kb)})
    except (PermissionError, OSError):
        budget.deny(path)
    results.sort(key=lambda result: result["size_kb"], reverse=True)
    return results[:limit], budget.warnings


# macOS

def run(command, timeout=180):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def du_children(path, min_kb=51200, limit=40, exclude_roots=()):
    if not os.path.isdir(path):
        return [], []
    started, results, warnings = time.monotonic(), [], []
    try:
        entries = list(os.scandir(path))
    except PermissionError:
        return [], [{"path": path, "reason": "权限不足"}]
    for entry in entries:
        if len(results) >= limit:
            break
        if time.monotonic() - started >= DEFAULT_MAX_SECONDS:
            warnings.append({"path": path, "reason": "超过扫描时间上限"})
            break
        if any(is_within(entry.path, root) for root in exclude_roots) or is_reparse_or_link(entry.path, entry):
            continue
        output = run(["du", "-sk", entry.path], timeout=120)
        match = re.match(r"\s*(\d+)", output)
        if match and int(match.group(1)) >= min_kb:
            kb = int(match.group(1))
            results.append({"name": entry.name, "path": entry.path, "size_kb": kb, "size_h": human(kb)})
    return sorted(results, key=lambda result: result["size_kb"], reverse=True), warnings


MAC_DEV_CACHE_PATHS = [
    "~/Library/Caches/pip", "~/Library/Caches/uv", "~/.cache", "~/.cargo", "~/.npm", "~/.pnpm-store",
    "~/.gradle", "~/.m2", "~/Library/Developer/Xcode/DerivedData", "~/Library/Developer/CoreSimulator",
    "~/Library/Developer/Xcode/iOS DeviceSupport", "~/Library/pnpm", "~/go/pkg", "~/.docker",
]


def system_info_macos():
    total = used = free = "?"
    try:
        disk = shutil.disk_usage("/")
        total, used, free = human(disk.total // 1024), human(disk.used // 1024), human(disk.free // 1024)
    except OSError:
        pass
    disk_info = run(["diskutil", "info", "/"])
    filesystem = re.search(r"File System Personality:\s*(.+)", disk_info)
    return {"os": "macOS " + run(["sw_vers", "-productVersion"]).strip(), "build": run(["sw_vers", "-buildVersion"]).strip(), "arch": run(["uname", "-m"]).strip(), "user": os.environ.get("USER", ""), "home": HOME, "filesystem": filesystem.group(1).strip() if filesystem else "APFS", "disk_total": total, "disk_used": used, "disk_free": free, "purgeable": "", "disk_name": "Macintosh HD", "disks": [{"name": "Macintosh HD", "total": total, "used": used, "free": free}]}


def scan_macos():
    library = os.path.join(HOME, "Library")
    dev_paths = [os.path.expanduser(path) for path in MAC_DEV_CACHE_PATHS]
    targets = [("home", HOME, 102400, [library, os.path.join(HOME, "Downloads")] + dev_paths), ("library", library, 51200, [os.path.join(library, name) for name in ("Caches", "Containers", "Group Containers", "Application Support")]), ("caches", os.path.join(library, "Caches"), 51200, []), ("containers", os.path.join(library, "Containers"), 51200, []), ("group_containers", os.path.join(library, "Group Containers"), 51200, []), ("app_support", os.path.join(library, "Application Support"), 51200, []), ("applications", "/Applications", 102400, []), ("downloads", os.path.join(HOME, "Downloads"), 51200, [])]
    groups, warnings = {}, []
    for key, path, floor, excludes in targets:
        groups[key], group_warnings = du_children(path, floor, exclude_roots=excludes)
        warnings.extend(group_warnings)
    dev, dev_warnings = [], []
    for path in dev_paths:
        rows, row_warnings = du_children(os.path.dirname(path), 51200, limit=1, exclude_roots=())
        dev_warnings.extend(row_warnings)
        if os.path.isdir(path):
            output = run(["du", "-sk", path], timeout=180)
            match = re.match(r"\s*(\d+)", output)
            if match and int(match.group(1)) >= 51200:
                kb = int(match.group(1)); dev.append({"name": os.path.basename(path), "path": path, "size_kb": kb, "size_h": human(kb)})
    groups["dev_caches"] = sorted(dev, key=lambda result: result["size_kb"], reverse=True)
    warnings.extend(dev_warnings)
    return system_info_macos(), groups, [], warnings


# Windows

def system_info_windows():
    import platform
    total = used = free = "?"
    system_drive = os.environ.get("SystemDrive", "C:") + "\\"
    try:
        disk = shutil.disk_usage(system_drive)
        total, used, free = human(disk.total // 1024), human(disk.used // 1024), human(disk.free // 1024)
    except OSError:
        pass
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = letter + ":\\"
        if os.path.exists(root):
            try:
                disk = shutil.disk_usage(root)
                drives.append({"name": root, "total": human(disk.total // 1024), "used": human(disk.used // 1024), "free": human(disk.free // 1024)})
            except OSError:
                pass
    return {"os": platform.system() + " " + platform.release(), "build": platform.version(), "arch": os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine()), "user": os.environ.get("USERNAME", ""), "home": os.environ.get("USERPROFILE", HOME), "filesystem": "NTFS", "disk_total": total, "disk_used": used, "disk_free": free, "purgeable": "", "disk_name": system_drive, "disks": drives}


def scan_windows_paths(profile, local, roaming, temp, program_files, program_files_x86, min_kb=51200):
    """Scan non-overlapping Windows ownership ranges; exposed for regression tests."""
    dev_paths = [os.path.join(profile, name) for name in (".cache", ".npm", ".gradle", ".m2", ".nuget", ".cargo")] + [os.path.join(local, name) for name in ("pip", "Yarn", "uv", "ms-playwright", "go-build")]
    downloads = os.path.join(profile, "Downloads")
    profile_excludes = [os.path.join(profile, "AppData"), downloads] + dev_paths[:6]
    local_excludes = [temp] + dev_paths[6:]
    targets = [("user_profile", profile, profile_excludes), ("appdata_local", local, local_excludes), ("appdata_roaming", roaming, []), ("temp", temp, []), ("downloads", downloads, []), ("program_files", program_files, []), ("program_files_x86", program_files_x86, [])]
    groups, denied, warnings = {}, [], []
    for key, path, excludes in targets:
        budget = ScanBudget()
        groups[key], group_warnings = scandir_children(path, min_kb=min_kb, exclude_roots=excludes, budget=budget)
        denied.extend(budget.denied); warnings.extend(group_warnings)
    dev = []
    for path in dev_paths:
        if not os.path.isdir(path):
            continue
        budget = ScanBudget()
        size = dir_size_bytes(path, budget)
        denied.extend(budget.denied); warnings.extend(budget.warnings)
        if size // 1024 >= min_kb:
            dev.append({"name": os.path.basename(path), "path": path, "size_kb": size // 1024, "size_h": human(size // 1024)})
    groups["dev_caches"] = sorted(dev, key=lambda result: result["size_kb"], reverse=True)
    return groups, list(dict.fromkeys(denied)), warnings


def scan_windows():
    profile = os.environ.get("USERPROFILE", HOME)
    local = os.environ.get("LOCALAPPDATA", os.path.join(profile, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(profile, "AppData", "Roaming"))
    temp = os.environ.get("TEMP", os.path.join(local, "Temp"))
    groups, denied, warnings = scan_windows_paths(profile, local, roaming, temp, os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    return system_info_windows(), groups, denied, warnings


def main():
    started = time.time()
    if sys.platform == "darwin":
        system, groups, denied, warnings = scan_macos()
    elif sys.platform.startswith("win"):
        system, groups, denied, warnings = scan_windows()
    else:
        print(json.dumps({"error": "unsupported_platform", "platform": sys.platform, "message": "scan.py supports macOS and Windows only."}, ensure_ascii=False))
        return
    print(json.dumps({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "system": system, "groups": groups, "denied": denied, "warnings": warnings, "scan_seconds": round(time.time() - started, 1)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
