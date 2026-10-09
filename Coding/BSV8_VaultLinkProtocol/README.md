# VaultLink v2 参考 SDK

`@vaultlink/sdk@0.2.0-draft.1`，尚未发布。wire version=2，与旧 0.1 帧/操作不兼容；没有旧协议降级分支。

```sh
npm ci --ignore-scripts
npm test
```

需 Node 22+、Python 3、C++17 编译器；浏览器部分依赖安全上下文中的 WebCrypto X25519/AES-GCM 与 Web Serial。完整 Edge 无头页面及当前 ESP32 板真实 USB 20 项集成检查已通过；产品 PIN/屏幕及电气断电专项尚未验收。密码依赖版本固定在 package-lock；此目录不包含生产私钥。

## 模块与职责

| 模块 | 已实施 |
| --- | --- |
| bytes / cbor / frame | Uint8Array、uint64 bigint、严格规范编码、有界流解析/CRC |
| crypto / handshake / session | 实际 X25519/HKDF/AES-GCM、配对码、受限持有权证明、当前 Key 绑定 |
| transport / client | WebSerial 适配、加密请求/结果、控制操作、心跳、未知不重试 |
| requests / device | 单活动业务、最近结果/水位、查询取消、注册真实操作、锁定回调 |
| payment | 单笔/跨渠道 App 会话预算、配置修订、并发预占/持久提交/恢复 |
| bsv / payment-operation | 实际 P2PKH 前序/脚本核验、基础金额、0x41 DER 签名与额度执行器 |
| src/node-store.mjs | 真实 Node 原子文件保存，单执行实例；不提供防回滚或硬件安全保证 |
| device/core.hpp | 无动态分配 C++ 帧解析、水位状态、额度数学 |
| device/sdk/ | 严格 CBOR、mbedTLS 握手/记录加密、P2PKH 核验/签名、App 持久额度、设备 Endpoint 与 Arduino 串口适配 |
| integration/ | Web/ESP32/Playwright/原生集成测试子项目；与产品仓库独立 |

## 接入方式

主机 Window 在用户手势中取得串口权限，把 port 传入 `WebSerialTransport.open`，再调用 `connectHost(transport, generations, expectedPublicKey, secpIdentityVerifier, confirmPairing)`。confirmPairing 负责显示/核对配对码；不能无条件 true 代替产品确认。随后持续运行 `client.run()`，使用 execute 提交完整信封。SDK 不读取 Keymaster 数据库、不连接 App、不广播交易。

设备在本地 PIN 解锁后创建 DeviceKey，调用 acceptDevice，配对确认回调连接真实按钮。再创建 DeviceServer 并注册 P2pkhPaymentOperation；owner/kind/App sessionId 必须来自执行端可信协调器，不能从支付 body 取任意文本。自动额度内 authorize 不唤起确认回调，超限回调取得用户对实际对象/额度的批准。

`new DeviceServer(session, () => { key.close(); policy.lock(); })` 是最小清理模式；产品还需结束 USB 链路关联的所有 App 会话。onLock 可异步，但必须先在执行端阻断密钥访问。DeviceIdentityKey 仅是设备执行器参考，不负责 PIN/私钥存储；不能让页面获得硬件 key 对象。

新连接创建新的 client/握手/记录状态。PaymentPolicy.open 从真实存储装载配置，并把旧会话置 inactive、旧 reserved 转 unknown；不自动恢复可签名请求。务必阅读 [断电重连规范](../../spec/v2/03-断电与重连.md)。

C++ 接入通过 `Endpoint`、`ByteTransport`、`Store` 和操作 factory；配对回调必须由产品提供，断链自动锁定 IdentityKey，产品断链回调结束相关 App 会话。Arduino 串口适配在 SDK 中；ESP32 Demo 的 NVS/启动计数与授权脚本在 `integration/esp32`。SDK 不管理操作系统 USB 驱动、PIN 存储或屏幕按钮。

P2PKH 主机承诺需要对原始交易做相同核验，完整核心为 `{rawTx,prevTransactions,channelId,paymentId,amount}`；amount 是外部输出合计，不包含矿工费/本人找零。`commitment('bsv-payment',1,core)` 与提交的 body 配合。设备仍重新核算，不相信主机 amount。底层 `p2pkhSighash` 仅计算摘要，不是签名入口。

## 当前限制与施工门禁

- 尚未实现渠道配置/读取/确认与 App 会话建立的 USB 操作。PaymentPolicy 是真实内部逻辑，不能据此声称硬件配置同步完成。
- 费用池具体阶段/脚本尚待共同冻结；只存在增量数学 helper，禁止宣称费用池签名支持。Channel/Local Secret/迁移/导入导出/PIN 不提供占位成功实现。
- wire 明文 896 字节单帧；完整前序证据使大部分多输入交易装不下。产品接入需明确可用交易范围，不能先移除证据核验。
- 固定 32 渠道、16 个保留会话、256 条支付记录；达到容量停止，不清理安全证据。安全归档/回收尚未完成，因此不适合宣称无限持续可用。
- Node 文件存储只有单实例权威契约，不能让多个进程共享一个额度账本，也不能冒充 ESP32 抗回滚持久实现。
- C++ 当前实现覆盖 mainnet/App/P2PKH，并与 TypeScript 执行端账本做恢复互通；插件渠道、费用池及其它 Profile 未覆盖。固件 GPIO/屏幕/PIN、生产私钥存储与 Keymaster 产品接入归各自项目。

测试执行真实密码实现、独立 Python 向量、真实文件写入及 WHATWG 字节流；字节流端到端通过不等于 USB 硬件通过。原项目旧 conformance 另外运行，本目录不修改旧报告。

## 独立 SDK 集成测试

见 [集成测试子项目说明](./integration/README.md)。`npm run integration:native` 运行真实 TS ↔ C++ 20 项互通检查；`npm run integration:page` 使用 Microsoft Playwright 和完整 Edge 无头浏览器；`npm run integration:firmware` 只构建测试固件。测试板接入后执行 `npm run integration:flash-test` 自动上传并运行真实 USB 序列，无需手动断电或按按钮。公开测试密钥/自动配对仅在 Demo 使用，不能用于生产钱包。
