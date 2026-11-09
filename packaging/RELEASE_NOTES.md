# FRP Ban v1.1.0

本版本新增 client 独立发布包，server 和 client 均支持 Windows、macOS 及 Linux 的 x64 / ARM64。
同时包含 v1.0.0 之后的 TLS、协议校验、封禁持久化和日志监控改进。

## 发布与安装包

- GitHub / GitLab 使用相同脚本发布，按组件和运行平台分别构建。
- 共提供 32 个安装包或便携压缩包，以及覆盖全部文件的 `SHA256SUMS`。
- server 文件名前缀为 `frp-ban-`，client 为 `frp-ban-client-`；两者可独立安装，也可在同一台机器上共存。
- 每个包包含完整 .NET 运行时、配置示例和许可证；client 另附 `rules.d` YAML 规则。
- Linux client 包附带独立账户、启动命令、systemd / OpenRC 服务，升级时保留配置和规则。

| 平台 / 发行版 | 架构 | 下载格式（server / client 均提供） |
| --- | --- | --- |
| Windows | x64、ARM64 | `.zip` |
| macOS | Intel x64、Apple Silicon ARM64 | `.tar.gz` |
| Debian / Ubuntu | x64、ARM64 | `.deb` |
| Fedora / RHEL / Rocky / AlmaLinux / openSUSE | x64、ARM64 | `.rpm` |
| Arch Linux / Arch Linux ARM | x64、ARM64 | `.pkg.tar.zst` |
| Alpine Linux（musl） | x64、ARM64 | `.apk` |
| Linux 便携版（glibc / musl） | x64、ARM64 | `.tar.gz` |

### Arch Linux 安装

下载所需组件；x64 安装示例：

```sh
sudo pacman -U ./frp-ban-1.1.0-linux-x64.pkg.tar.zst
sudo pacman -U ./frp-ban-client-1.1.0-linux-x64.pkg.tar.zst
```

Arch Linux ARM 请将文件名中的 `linux-x64` 替换为 `linux-arm64`。

- server 配置：`/etc/frp-ban/appsettings.json`；服务：`frp-ban`。
- client 配置：`/etc/frp-ban-client/appsettings.json`；规则：`/etc/frp-ban-client/rules.d`；服务：`frp-ban-client`。
- 安装后不会自动启用或启动服务。请先配置 Token、TLS 证书 / 信任链及日志规则，再按需执行 `sudo systemctl enable --now frp-ban` 或 `sudo systemctl enable --now frp-ban-client`。
- `frp-ban-client` 账户需要具有被监控日志及其父目录的读取 / 访问权限，并在日志轮转后继续生效。
- 默认 SSH 规则使用 `/var/log/auth.log`，请按本机日志路径调整；`journal` 日志源尚未实现。

## 安全改进

- 严格校验协议帧长度和必填 JSON 字段，限制输入大小并拒绝截断、超长或格式错误的消息。
- 完善自定义 CA、服务器名称、证书有效期和 mTLS 客户端证书用途校验。
- 增加握手、读写超时及连接 / 消息速率限制，限制每 IP 状态占用。
- frps HTTP 回调在读取请求体之前校验来源地址，默认仅监听 loopback；规范化 IP 并拒绝无效请求。
- 启动时校验 Token 和嵌套配置；规则加载时校验表达式，缓存正则并设置执行超时。

## 稳定性与性能

- 串行化 client 协议交互，断线期间通过有界队列保留待发送的封禁请求，重连后重试。
- 封禁文件采用单写入器合并更新和原子替换，避免并发持久化覆盖；损坏数据会使启动失败。
- 日志读取保留不完整 UTF-8 行，处理文件轮转和超长输入，避免并发读取冲突。
- 对阈值统计状态设置容量与过期限制，修复 JSON 匹配条件和 IP 提取逻辑。
- 整理共享协议、TLS 校验、日志监控及测试项目结构，统一构建属性和 NuGet 版本管理。

## 升级注意事项

- 建议 server 和 client 一起升级，并先备份原有配置、证书、规则和封禁数据。
- server / client 必须配置相同的非占位 Token，长度至少 32 个字符；默认示例不能直接用于启动。
- TLS 校验更严格：私有 CA 或自签证书需要配置受信任 CA，证书名称必须匹配连接地址；服务器要求 mTLS 时还需配置有效客户端证书。
- frps 不在本机时，需要显式配置 HTTP 监听地址及可信回调来源。
- client 待发送队列只保存在内存中，进程退出后不会持久保存。
- Windows / macOS 请完整解压，配置后通过 `frp-ban[.cmd]` 或 `frp-ban-client[.cmd]` 启动；Linux 原生依赖仍需由系统提供，Alpine 包未签名。
- 完整安装、依赖及配置步骤见本标签的 `docs/RELEASING.md`，下载后请使用 `SHA256SUMS` 校验文件。

## 验证

- 115 项 .NET 单元及集成测试通过。
- 15 项发布脚本测试通过，覆盖双组件、8 个运行平台、Arch 包配置、归档内容、校验清单及 GitLab 资产上传逻辑。
