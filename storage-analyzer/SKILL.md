---
name: storage-analyzer-safe
description: >
  macOS / Windows 的有界、只读存储分析助手。扫描磁盘占用并生成静态 HTML
  报告，将候选项分为可自动清理、需人工判断和谨慎清理；只提供可复制的建议，
  不提供网页删除、回收站或本地文件操作接口。用户提到“存储分析”“磁盘满了”
  “C盘/硬盘满了”“空间不够”“清理空间”“disk cleanup”“storage analysis”时使用。
  用户明确询问 RAM/进程内存占用时不使用本 skill。
---

# Storage Analyzer Safe

产出流程固定为：**有界只读扫描 → 分析分级 → 生成静态报告 → 给出摘要**。报告没有 HTTP 服务、网络请求、删除按钮或本地文件操作接口。

## 安全边界

- 只能运行扫描、统计、列目录和读取元数据；禁止 `rm`、`mv`、`rmdir`、清空回收站、改权限或其他写操作。
- 报告中的命令仅供用户自行确认后执行。即使用户要求代删，也必须在对话中单独确认，且不应复用本 skill 的报告或脚本执行删除。
- 扫描跳过符号链接和 Windows junction / reparse point，避免越界遍历、循环和重复统计。
- 扫描受目录项数、目录深度和时间预算限制。权限不足、跳过项和预算中止会写入 `denied` / `warnings`；这意味着结果可能不完整，不能当作 0 字节。
- Windows 扫描将 `AppData`、`Downloads`、开发缓存和 `Temp` 分配给互不重叠的组，避免跨组汇总时重复计量。

## 执行流程

### Step 1：扫描（只读）

在 skill 目录中运行：

```bash
# macOS
python3 scripts/scan.py > /tmp/storage_scan.json

# Windows PowerShell
py -3 scripts/scan.py > "$env:TEMP\storage_scan.json"
```

输出包含 `system`、按目录归属划分的 `groups`、`denied`、`warnings` 和 `scan_seconds`。仅将已完整或明确标注为局部结果的范围用于空间估算；在摘要和报告中保留遗漏提示。

### Step 2：分析与分级

根据 `system.os` 读取 [references/macos.md](references/macos.md) 或 [references/windows.md](references/windows.md)。从扫描结果中选出确实存在清理决策的目录：

- 🟢 **可自动清理**：明确可再生的缓存或临时文件。提供估算空间、需关闭的进程与**可复制**命令。
- 🟡 **需人工判断**：含用户数据或不确定内容。提供内容画像、风险及具体人工处置路径；不提供可操作路径数组。
- 🔴 **谨慎清理**：应使用正式卸载或应用内流程的应用/核心数据。说明风险和正规释放步骤。

所有释放量都标为估算。不要把系统文件、正常应用或未扫描区域包装成可清理建议。

### Step 3：生成静态只读报告

将分析结果写为 JSON（字段可选：`system`、`top5`、`green`、`yellow`、`red`、`denied`、`warnings`、`summary`），然后生成单文件报告：

```bash
# macOS
python3 scripts/build_report.py /tmp/storage_analysis.json ~/Desktop/storage-report.html

# Windows PowerShell
py -3 scripts/build_report.py "$env:TEMP\storage_analysis.json" "$HOME\Desktop\storage-report.html"
```

报告可离线打开和分享。它会安全转义 JSON 中的 `<`、`>`、`&` 与 JavaScript 行分隔符，路径或分析文本即使包含 `</script>` 也不会成为可执行 HTML。

### Step 4：对话摘要

先给结论：估计可释放空间、最值得先处理的 2–3 项、最高风险项，以及是否存在 `denied` / `warnings` 导致的统计盲区。细节由静态报告承载。

## 运行前提

- 仅 Python 3 标准库，无需 `pip install`。
- macOS 使用系统自带 `du`、`diskutil` 和 Python 3。
- Windows 使用 `py -3` 或 `python`；首次使用前应先运行内置回归测试。

## 平台状态

- macOS 与 Windows 均为只读扫描和静态报告路径。
- Windows 对 reparse point 的处理基于标准库文件属性；在目标机器启用前先运行 `py -3 -m unittest discover -s tests -p "test_*.py" -v`。
- `server.py` 仅保留为兼容桩文件：运行后会提示改用 `build_report.py` 并退出；它不监听端口、不打开浏览器，也不支持网页一键删除、回收站或永久删除。
