# VaultLink v2 参考 SDK

> 2026-10-10 最终施工记录：[三项目施工验收](../../reports/2026-10-10-三项目施工验收.md)。同 Key 双向迁移及恢复、三按钮导入 PIN、有限安全归档、普通未签名预览/显式预签已完成代码施工；旧“继续施工/不支持”条目保留为历史。实体 USB、按键和 Flash 掉电另行验收，不能用宿主测试代替。本期不做信用信息。


> 当前支持及验收边界见本文末尾“受限签名收口与迁移账本转换”；前面的增量条目保留历史状态。

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


## 2026-10-10 标准交易、分片与会话取消增量

已实施：VLP 标准单钥脚本解析及 TS/C++ 固定 0x41 签名；Keymaster protocol spend 的手续费迭代不签名，稳定交易由唯一额度核心签署，输入在等待批准前领取 claim；BitFS 通用 FundingTx 支持单池输出。加入 32 KiB 有界认证分片（原帧/密码不变）、消息串行发送和帧类型绑定。产品能力为 Draft 0x224。

软件 App 关闭请求页立即撤销未执行申请与待批准，恢复同一连接保留累计额度。Window/Worker MessagePort USB 字节桥已实现并在实际 C++ Endpoint 互通中使用；它尚未装配到 Keymaster 钱包生命周期和设置界面，不等同于产品硬件绑定已完成。

BitFS 卖方 Kind 2 先预签、Kind 4 才收完整资金原文。已撤回错误复用付款方前序路径的生产接线，现有软件卖方流程保留。后续必须补可核验的开池预签 Profile 和实际阶段联测，不能开放硬件任意摘要作为替代。迁移、Channel/本地秘密、其它资金入口、安全归档及真机验收继续保留未完成状态。

验证：VLP 38/38；产品 SDK/C++ 与软件核心集成 6/6；Keymaster 53 文件/504 业务用例通过；类型、107 契约结构、73 契约用例、310 模块 Worker 边界及自检通过。以上是主机验证，不是浏览器 USB、实体按键或掉电验收。

追加验证：支付核心在预占后、签名开始前同步检查取消，确定未签的失败释放预占并保留不可复用墓碑；已经进入私钥运算的失败仍保留未知额度。实际交易、真实签名和磁盘账本测试通过，产品集成更新为 7/7。软件超额 UI 真 Worker 检查 1/1 通过。RocKey 英文/简体中文发布固件与 ELF 扫描通过，构建 ID `20261009T175300Z-0156bb1`；没有刷机或真实资金广播。SDK 两份 vendor 文件与 manifest 哈希逐一一致。


## 2026-10-10 本地秘密兼容施工

硬件绑定检查确认：钱包恢复数据需要 v3 LocalSecret。已按冻结配方增加正式 C++ 封装/解封、SDK 严格范围/信封校验、Keymaster 硬件代理以及 RocKey 实体审核，产品 Draft 能力 0x225。HKDF 和长期派生密钥保留在设备内；秘密正文不进入设备审核页。支持明文 1..512 字节、scope 1..95 UTF-8 字节。大信封仍走既有有界加密分片。

秘密缓冲处理包括：原私钥/HKDF 临时材料清理；C++ 协议值替换、销毁和连接关闭清理；完整请求编码、分片编码、解密记录清理；取消连接世代后，硬件代理不交付迟到解封明文。JavaScript 清理是应用层缓冲处理，不宣称消除运行时/系统内存副本。

验证直接使用 Keymaster 现有 WorkerKeySession 与 VaultOperationExecutor 产生旧 v3 密文，实际 C++ 实现可解封；C++ 封装结果也可由现有软件解封，覆盖 1/32/512 字节。换 Key、换 scope、锁定、篡改、超长和非法范围均拒绝。正式 C++ Endpoint 与硬件代理通过加密字节桥执行 512 字节往返及错误后再次正常解封。确认来源为宿主测试 ApprovalUI，不是实体按键验收。

当前仅本次实体确认。持续许可/否决及撤销、硬件公开钱包记录、解锁与唯一桥的生命周期装配、同 Key 双向迁移仍未完成；本次不是完整硬件钱包交付，也没有刷机、熔丝或资金广播。

本增量验证记录：VLP 39/39；正式产品 SDK/C++ Endpoint 集成 7/7；旧软件与 C++ 密文双向兼容及原有 Worker 核心回归 3 文件/6 用例通过；类型、107 契约结构、73 契约用例、311 模块 Worker 边界与自检通过。RocKey 英文/简体中文发布固件和 ELF 扫描通过，构建 ID `20261009T181326Z-0156bb1`。两端 SDK vendor manifest 哈希逐项一致。没有真实 USB/按键或掉电验收。


## 2026-10-10 本地秘密持续决定与设备撤销菜单

已实施：新协议 PaymentService 的本次允许/否决、当前 USB 连接内持续允许/持续否决、精确操作+scope 匹配、修订撤权栅栏；ScopeGrants 为有界易失状态，容量 8，与原设备菜单容量一致，不自动淘汰持续否决。断链清空、旧准备请求失效；付款渠道/会话账本不因这些操作清空。产品能力更新为 Draft 0x226，请求结构和承诺保持不变，主机没有设置持续决定的接口。

三按钮：基础内容读完后短按 B 切换本次/会话，长按 B 同意，长按 A 否决。原“会话决定”菜单已改读新协议授权，完整显示一项的操作、允许/否决及范围；A/C 前后项，B 短按撤当前、长按撤全部，A 长按返回。共享 UTF-8 安全分行，避免截断字符或用截短标签识别待撤权限。软件本地秘密仍由已解锁 Worker 直接执行，没有增加软件确认窗。

验证：正式产品 PaymentService、真实密码、磁盘 Store 的持续决定测试通过，包括本次不持久、跨操作不共用、持续否决不重复弹出、两种决定撤销后重新询问、撤销使旧请求失效、满额不淘汰、断链清空和 UTF-8 完整性。Keymaster 产品集成更新为 8/8；现有软件/C++ v3 密文兼容测试仍通过；类型、107 契约结构、73 契约用例及 311 模块 Worker 边界与自检通过。生产构建通过。RocKey 英文/简体中文固件与发布 ELF 扫描通过，构建 ID `20261009T182700Z-0156bb1`。

宿主测试的决定来自明确标记的 HostDecision 输入适配，不冒充实体按钮。尚未做真 USB/按键/掉电验收，也未刷机或广播真实资金。硬件公开钱包记录、解锁/USB 生命周期装配、同 Key 双向迁移和其它原施工项仍未完成，不勾整项通过。

## 2026-10-10：受限签名收口与迁移账本转换（阶段记录）

本节是截至本次施工的当前状态；前面各日期/增量记录保留为历史证据，不把旧的“尚未支持”作为当前支持清单。

| 范围 | 当前代码及验证 |
|---|---|
| Connect 身份/意图 | exact Connect v1 CBOR 信封；公钥、内容摘要、规范编码核验；设备本次物理决定，返回严格 low-S DER，主机验证后转换为 compact；无通用摘要回退 |
| Channel | 实际 SDK 0.6.0 public/hash/private、seal/open 双向兼容；有界 JCS 与固定域分隔；设备 ECDH/HKDF/AES-GCM；按操作/对方/协议持续许可、否决、撤销与断线失效 |
| BitFS 消息 | exact wire 文档 kinds 1/6/8/9/10/11；设备重建原业务域摘要并解释基础字段；Kind 5 不得绕过金额核心 |
| BitFS Kind 5 付款授权 | 完整 funding、退款及未签付款原文核验，先按累计增量占用额度再签署；随后 Kind 7 同一付款不重复计额；未知结果保留占用 |
| BitFS 卖方开池 | Kind 2→3 的独立 bsv-feepool-bitfs-opening；按实际 v4 规范退款和费率推导池金额，核验买方 low-S DER || 0x41；未收到 Kind 4 时不伪造前序交易；后续协签读取真实日志 funding |
| 网络身份 | 设备重建 Noise 固定域或自己的无地址 Peer Record，覆盖 uint64 序列号；主机仍执行 executor 租约/世代/单调性校验；无任意签名、PeerId 或地址输入 |
| 迁移账本基础 | encode/decodePaymentPolicy 使用实际 C++ v2 bank，完整保留 uint64、关闭会话、已消费及未知付款、池基线、修订；同 Key 和容量/支持检查，不授予导入/清空账本权限 |

当前产品声明 wire 2 / SDK 0.2.0-draft.1 / Draft 0x22d。0x228 是 Connect；0x229 是 Channel；0x22a 是 BitFS 文档；0x22b 纳入 Kind 5 金额；0x22c 是网络身份；0x22d 是卖方开池预签。具体规范见 VLP spec/v2/04..07，握手及三消息不变。

本次验证：VLP SDK 52/52（包含实际 C++ Policy、磁盘账本与 ASAN/UBSAN）；Keymaster SDK/实际 RocKey C++ 宿主互通 12/12；Connect/Channel/BitFS/网络签名与原 SDK 独立验签，双向 Channel 封装；相关软件/买方状态/卖方协议/契约回归 5 文件 42 用例。类型、107 契约结构、73 契约用例和 324 个 Worker 模块边界/自检通过。插件依赖索引按真实当前源码重新生成，743 调用点。

RocKey 最新五语言发布构建 ID 20261010T064015Z-0156bb1，en/zh-Hans/zh-Hant/zh-Hk/ja 全部编译及 ELF 扫描通过；248 条译文齐全。逐语言 firmware.elf、firmware.bin、font-MANIFEST.md 已归档在 .pio/releases/<build-id>/<env>。构建后默认简体中文字体重新生成，462 字形、位图 64774 字节。两端 SDK vendor 全部文件哈希逐项核验，sourceOverrides 明确标注未提交工作区增量，不冒称基准提交已有这些代码。

未完成部分仍明确保留：同 Key 双向私钥迁移及设备重新 PIN、导入/主动导出、迁移 journal、崩溃恢复和真正预算转移；安全归档/回收；Keymaster 信用服务的实际来源配置与接入；真实浏览器/USB、实体按钮/PIN、重启及掉电验收。账本转换和仓储 CAS 是迁移基础，不能据此把 K5/R4 或完整迁移勾成完成。账本满额仍 fail closed，不能删签名/未知付款、关闭会话或池基线来清空额度。信用查询/Markdown 继续只归 Keymaster，不新增设备信用业务。

宿主 C++ 审核决定由明确标记的 HostApproval/UI 适配提供，不能算实体按钮通过。当前机器只发现 Bluetooth/debug/wlan 串口，未发现 M5Stack；未刷机、熔丝或广播真实资金。迁移仍显式不支持，硬件启用发现软件旧 payments.json 时拒绝，不能以空设备预算代替迁移。


## 2026-10-10：硬迁软、独立擦除与回执恢复（阶段进度，已由最终记录更新）

本节替代此前“所有私钥迁移显式不支持”的阶段状态，只收口已有同 Key 迁移需求；不新增信用查询或业务解释功能。

- [x] VLP 设备公开 journal：SDK TS/C++ 严格九字段、规范 CBOR、同绑定及线性阶段校验；真实记录持久化。Draft 0x22f / migration.status 只读公开状态，不授予密钥操作。
- [x] RocKey 主动导出与重新 PIN：本机菜单开启导出；A/C 选择数字、B 输入、长按 B 删除、长按 A 拒绝。复用 KeyStore 真实失败计数与等待；PIN 输入清零，成功后重新松键、读完摘要/风险、长按仅本次确认。持续许可和浏览器字段均不能代替。
- [x] Draft 0x230：migration.export 输出前持久化 device-committed；私钥经原加密 USB 仅传一次，query/replay 只保留完成状态。Worker 实际派生核对公钥，生成并解密回读验证新密码 KeyHold。源私钥、回读副本及异常路径缓冲清零。
- [x] Keymaster 硬迁软主流程：Worker 钱包迁移门禁排空已有 I/O，阻断新业务读写/签名；同一 IndexedDB 事务写目标 KeyHold、完整真实额度 bank 和 local-committed journal，保留身份世代、公钥、联系人、消息和其余业务记录。Window/插件只取得公开 DTO。
- [x] 独立硬件擦除：浏览器真实提交后发送公开 host-commit，不能由此自动擦除。设备再一次 PIN 与实体仅本次确认，先记录 erasing，再执行真实清理并清除 KeyStore/运行时两份 RAM 私钥，最后记录 erased。只有匹配浏览器提交的擦除回执才完成 journal；钱包锁定后用新密码解锁。
- [x] 旧 Key 仍在的恢复：专用连接重新验证同一原 Key，核对原 journal；prepared/device-committed 仍需本机重新开启导出、重新 PIN。local-committed 只继续原目标的确认/擦除，不重新封装或改写目标。恢复期间没有普通业务解锁。
- [x] 已无旧 Key 的回执恢复：Draft 0x231 使用 RAM 临时身份和实体配对，只核对浏览器已经原子提交的同一 journal/KeyHold/bank。临时公钥不写钱包记录、不冒充旧私钥持有权。设备只开放 status、recover-erased、complete；普通签名明确拒绝。erasing 的剩余清理需独立实体确认，存在任何 Key 文件时绝不走此入口；已持久化 erased 只核对回执。
- [x] 产品 UI：Key 管理页“迁回软件钱包”收集新密码；存储阻断页通过 Vault 私有恢复组件继续同一迁移，可明确选择“设备已擦除，仅恢复回执”。配对、PIN、导出与擦除决定保留在设备。设备保留公开回执；确认浏览器完成后，用户才能独立长按重置设备，USB 不自动创建新身份。
- [x] SDK 清理：关闭期间晚返回的一次性结果、无等待方/绑定不合法的 decoded 回复清零；通用 query 无再次获取私钥的路径。Consumer 固定 SDK 包及 manifest 同步真实文件 SHA-256，并明确登记未提交源覆盖，不伪装已发布版本。

本阶段证据：SDK 57/57；产品原生加密互通 14/14；Keymaster 全量 315 文件 / 2713 用例；类型、744 调用点依赖、107 契约、74 契约测试及 331 Worker 模块边界通过；生产构建及 10 个产物扫描通过。RocKey 主机 1564 项检查通过，五语言发布构建及 ELF 门禁全部通过，Build ID `20261010T113241Z-0156bb1`。

测试执行真实生产协议、KeyStore/PIN 状态机、密码学、KeyHold、账本和事务代码。Node IndexedDB 介质、HOST LittleFS、按钮/配对决定均为明确命名的测试环境适配；erasing/erased 恢复测试明确使用提交点夹具，不冒充之前已经发生过的实体会话或 Flash 断电。当前串口只有 Bluetooth/debug/wlan，未连接 M5Stack；没有刷机、熔丝或真实资金广播，实体验收没有勾选。

剩余施工继续按原边界：软件同 Key 迁入新设备的私有 provisioner、设备进口 PIN/导入阶段恢复与产品向导；有界账本的安全归档回收；Connect ProtocolSpend prepare 的费用池阶段/预签收口；真实浏览器 USB、实体三按钮/PIN、重启和 Flash 掉电验收。migration.import 仍明确不支持，满账本继续 fail closed，不删除未知/已消费资金或防重放证据。K5/R4 整项及完整软硬替代不据此标记完成。信用信息本期完全不实施，也不作为交付阻断。
