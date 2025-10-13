# AnyIntruder 发布说明

## 版本 [你的版本号，例如：v1.0.0]

### 新功能
- 增加了对 Telegram Webhook 的支持。
- 实现了使用 `config.yaml` 统一配置 Webhook 的系统。

### 改进
- 优化了 `parse_platform` 函数，提高了平台检测的准确性。
- 改进了 `Makefile`，包含了所有必要的源文件进行编译。
- 将 `yaml_get_value` 函数重构到 `file_utilities.c` 中，提高了代码复用性。

### Bug 修复
- 解决了 `telegram.c` 中缺少字符串工具头文件导致的编译错误。
- 修复了通过更新 `Makefile` 解决的 `_webhook_send` 和 HTTP 客户端函数相关的链接错误。

### 已知问题
- [在此处列出此版本中存在的任何已知问题或限制，如果适用。]

感谢你的持续支持！