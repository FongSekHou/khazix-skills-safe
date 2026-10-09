# Windows 数据布局与分级参考

本参考只用于解释扫描结果和给出人工处置建议；本 skill 不删除、移动或打开本地路径。

## 多盘符

报告会列出所有盘符，但扫描重点是系统盘上的用户目录、AppData、临时目录与开发缓存。其他盘中的用户资料和游戏通常应归 🟡，由用户自行判断。

## 关键目录

| 目录（环境变量） | 常见内容 | 典型分级 |
|---|---|---|
| `%LOCALAPPDATA%` | 浏览器缓存、应用数据、Temp | 缓存 🟢 / 应用数据 🟡 |
| `%LOCALAPPDATA%\Temp`、`%TEMP%` | 临时文件 | 🟢 |
| `%APPDATA%` | 应用配置/数据 | 🟡 |
| `%USERPROFILE%\.cache`、`.npm`、`.gradle`、`.m2`、`.nuget` | 开发缓存与工具数据 | 需确认后多为 🟢 |
| `C:\Program Files` | 应用本体 | 🔴，走正规卸载 |
| `%USERPROFILE%\Downloads` 的安装包 | 安装包残留 | 🟢，但先确认仍不需要 |
| `C:\$Recycle.Bin` | 回收站 | 🟡，提示用户自行清空 |

## 扫描边界

- `user_profile` 不包含其下的 `AppData`、`Downloads` 和已单列的开发缓存；它们由各自组负责，避免重复统计。
- `appdata_local` 不包含已单列的 `Temp` 与开发缓存。
- 符号链接、junction 和其他 reparse point 会被跳过并写入 `warnings`。
- 目录项、深度或时间达到预算时，输出同样会写入 `warnings`。这不是目录大小为零。

## 系统占用

`C:\Windows\WinSxS`、`hiberfil.sys`、`pagefile.sys` 等系统内容不上三灯。建议使用 Windows 存储感知、磁盘清理或正规卸载器，而非手动删除系统目录。
