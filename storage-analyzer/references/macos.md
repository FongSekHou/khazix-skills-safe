# macOS 数据布局与分级参考

本参考只用于解释扫描结果和给出人工处置建议；本 skill 不删除、移动或打开本地路径。

## 关键目录

| 目录 | 常见内容 | 典型分级 |
|---|---|---|
| `~/Library/Caches/*` | 应用与工具缓存 | 🟢 |
| `~/.cache/*`、`~/.npm`、`~/.cargo`、`~/.gradle`、`~/.m2` | 开发缓存 | 🟢 |
| `~/Library/Developer/Xcode/DerivedData` | Xcode 构建产物 | 🟢 |
| `~/Library/Containers/*` | 沙盒应用数据 | 🟡 |
| `~/Library/Application Support/*` | 应用数据 | 🟡 |
| `~/Downloads` 的 `.dmg` / `.pkg` | 安装包残留 | 🟢，但先确认不再需要 |
| `/Applications/*.app` | 应用本体 | 🔴，走正规卸载 |

## 扫描边界

- `home`、`Library`、`Downloads` 和开发缓存由互不重叠的组统计，避免把同一目录加入多组。
- 符号链接会被跳过；权限不足或预算中止会写入扫描结果的 `warnings` / `denied`。
- UUID 命名容器应通过只读查看确认归属；含聊天记录、离线内容或配置的数据通常归 🟡。

## 系统占用

系统文件和 APFS 本地快照归“系统及其他”，不要手动删除。长期建议可包括存储空间设置、Xcode 缓存管理和正规应用卸载流程。
