# SDK 集成测试子项目

本目录独立测试 Web SDK 与 ESP32 SDK，不依赖 Keymaster、RocKey 或外部 App。USB 适配、编码、握手、加密、请求状态和断线处理属于 SDK；页面和 Demo 只组织测试及提供平台存储/测试授权。

## 目录与职责

| 子项目 | 职责 |
| --- | --- |
| `web/` | 加载真实 TypeScript SDK，使用浏览器 Web Serial；显示逐项结果、下载报告 |
| `esp32/` | ESP32 测试固件，调用 `device/sdk/`，真实 mbedTLS、USB-UART、NVS 和内部重启 |
| `runner/` | Microsoft Playwright + 完整 Edge 无头浏览器；选取真实设备、预授权、运行共同序列 |
| `native/` | 同一个 C++ Demo 的原生进程检查，实际管道和原子文件；便于无硬件时排查互通 |
| `artifacts/` | 生成的 JSON 报告、失败截图/trace、原生二进制；不入版本库 |

原生检查通过不代表 USB 或 ESP32 真机通过。页面检查通过不代表硬件通过。未连接硬件时，硬件入口报错，不跳过或补成功结果。

2026-10-09 已在 ESP32-D0WDQ6 + CP2104 (`10c4:ea60`) 实际上传并运行完整 Edge 无头 USB 序列：20 项通过、0 失败，无人工按键/授权点击/拔插。原始结果已保存到 [硬件验收结果](../../../reports/0006-SDK集成测试硬件结果.json)，具体边界见 [验证报告](../../../reports/0006-SDK集成测试施工与验证.md)。

## 准备与命令

在 `Coding/BSV8_VaultLinkProtocol` 执行，需 Node 22+、Python 3 和完整 Microsoft Edge。浏览器默认 `msedge`、headless；可通过 `VLP_BROWSER_EXECUTABLE` 指定完整 Edge 可执行文件。本机项目工具目录存在便携 Edge 时自动使用它，不安装到日常浏览器目录。

```sh
npm ci --ignore-scripts
npm test
npm run integration:prepare
npm run integration:page
npm run integration:firmware
```

原生互通检查另需 C++17 编译器及 mbedTLS 3 开发库：

```sh
# macOS 默认 /opt/homebrew/opt/mbedtls@3；其它安装位置显式指定。
VLP_MBEDTLS_PREFIX=/path/to/mbedtls npm run integration:native
```

准备完成后，把**测试用** M5Stack Core ESP32 插上，运行：

```sh
npm run integration:flash-test
```

该命令枚举真实 USB 串口，上传测试固件并自动完成 20 项测试。它会替换板上原固件；只使用测试设备。已刷入当前 Demo 可直接 `npm run integration:hardware`。多台设备时必须指定，例如：

```sh
VLP_SERIAL_PORT=/dev/cu.usbserial-example npm run integration:flash-test
```

可用 `VLP_USB_VID=0x10c4 VLP_USB_PID=0xea60` 筛选。Python 工具依赖在 `requirements.txt`，ESP32 平台固定 `espressif32@6.12.0`，当前构建目标为经典 M5Stack Core ESP32（USB-UART）；其它 ESP32/S3 原生 CDC 板需单独核验板型与上传配置，不能由当前构建推定兼容。

浏览器使用独立临时资料目录，预授权只针对选中 VID/PID 和 `http://127.0.0.1:4173`，测试结束删除；不改日常浏览器或系统策略，不替换 `navigator.serial`。预授权是 Chromium 注册 pref 的测试配置，浏览器升级后由页面检查验证是否仍然读取；实际授权仍须由真机 `getPorts/open` 验证。同 VID/PID 有多台设备时页面拒绝继续，请只连接一台匹配设备。

手工排查可 `npm run integration:serve` 打开页面，点击“授权设备”和“运行全部测试”；这是调试入口，自动运行无需点击。`integration:policy` 仅输出官方策略配置示例，不写入系统。

## 自动执行序列

| 编号 | 核查 |
| --- | --- |
| 01 | 实际配对、私钥持有证明、加密往返、测试固件身份 |
| 02 | 额度内 P2PKH 实际签名并独立验签；只计外部输出，不计矿工费/本人找零 |
| 03 | 同付款 ID 重放不签名、不重复累计 |
| 04 | App 累计超额：拒绝与仅批准本次 |
| 05 | 提高当前会话额度，不修改默认额度或单笔额度 |
| 06 | 等于单笔上限自动；超出后否决 |
| 07 | 同 App 跨渠道累计，换渠道不刷新预算 |
| 08 | 前序交易证据或承诺被篡改时拒绝 |
| 09–10 | 等待批准期间查询/取消可用、并发业务槽拒绝 |
| 11–14 | 预占前/预占后/签名后/提交后内部重启；检查新启动标识、旧会话失效、未知/已签支出保留 |
| 15–16 | 配置提交前后重启，分别保留旧/新配置 |
| 17 | 实际 Store 接口故障导致停止支付；重启读取真实持久状态 |
| 18 | 未实现操作返回 unsupported |
| 19 | 篡改真实 AES-GCM 密文并重算帧 CRC，断链、不签名、不恢复旧授权 |
| 20 | 错误预期公钥与拒绝配对不能连接；之后可重新连接 |

浏览器与原生共用 `runner/suite.mjs`。原生额外把 C++ 真正提交的账本复制后交给 TypeScript 恢复核查，避免两个权威同时写一个账本。

## 测试专用行为与边界

固件只使用**公开测试私钥标量 1**，生成本地公开交易材料，绝不广播、不接生产钱包密钥。授权脚本实际决定批准/否决/等待，测试不会要求屏幕按钮或 PIN。Demo 在断链锁定后自动重新加载公开测试密钥；产品必须接自己的 PIN 解锁，不能照搬这个测试行为。

`test.*` 控制接口受 `VLP_E2E_TEST_ONLY` 编译开关约束，生产 SDK 无注册入口；原生检查含独立编译门禁。渠道配置控制只给本次测试驱动调用真实额度引擎，**不是已冻结的产品渠道同步协议**。

ESP32 使用独立 NVS 命名空间 `vlp_e2e`，清理仅针对其中的测试账本/故障计划，启动计数持续保存。初始化或持久化失败保持不可用，不自动格式化整个 NVS。

内部 `esp_restart()` 清除运行内存并从 NVS 恢复，避免操作人员拔插；它验证业务恢复语义，不证明供电中断瞬间的 Flash 电气可靠性，也不覆盖 USB 桥重新枚举、三按钮/PIN/屏幕体验或真实人工确认。带电池/无电池产品的具体电源行为需后续真机专项检查。

当前 C++ 互通集为 mainnet/App/P2PKH；费用池、插件渠道、迁移、PIN 与产品 UI 不由这次 20 项检查声明支持。明文 896 字节和有界账本限制仍适用。

## 报告

- `artifacts/native-report.json`：明确 `hardware:false`。
- `artifacts/hardware-report.json`：真实 USB 序列的逐项结果、浏览器版本、SDK 版本和设备启动标识。
- `artifacts/playwright-report/`：浏览器报告。
- `artifacts/playwright-results/`：失败截图与 trace。

任何失败停止该序列并保留失败信息；重新运行从真实测试账本重新初始化。硬件报告只有真实 20 项完成才可标记通过。
