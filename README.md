# BSV8_VaultLinkProtocol

**BSV8 VaultLink Protocol（VLP）**：应用与密钥设备之间的语义操作、身份绑定、会话授权与结果交付协议。

当前施工版本 **VLP 0.2 Draft / wire 2**；原 0.1 保留为历史审计基线。本仓库维护共同规范、机器可读 schema、公开向量与兼容性工具。
Keymaster 与 Rockey 是首批参考接入方，**不是协议固有依赖**。

> 2026-10-09 当前范围见 [最小职责需求](./docs/密钥后端最小职责需求.md) 与 [施工单](./docs/密钥后端最小职责施工单.md)：设备基础签名核验/实体决定、PIN/密钥迁移、USB；信用/Markdown 归 Keymaster，软件无新增钱包批准。旧报告保留原范围，费用池及 USB 新版待重新冻结。

> 当前支付策略增加 [渠道单笔 + App 会话累计免确认额度](./docs/支付渠道与免确认额度需求.md)，超额确认可提高本会话额度；[施工单](./docs/支付渠道与免确认额度施工单.md) P0/P1 参考实现部分已实施；跨项目接入、生产配置同步及产品真机验收尚未完成。独立 SDK 的当前目标板 USB 测试已通过。

## 当前状态

| 阶段 | 状态 |
| --- | --- |
| V0 来源审计与冻结决策 | 已交付 |
| V1 schema / 公开向量 / conformance 基础 | 已交付 |
| v2 TypeScript Core、支付额度/P2PKH 参考执行器 | 已实施，见新版报告；尚未接入产品 |
| C++ 设备 SDK | 严格 CBOR/真实密码/P2PKH/App 持久额度及 USB 串口适配已实施；其它 Profile 待施工 |
| 独立 SDK 集成测试 | Web + ESP32 Demo + Playwright 已实施；原生 20 项及当前 ESP32 板真实 USB 20 项通过，Edge 页面/固件构建通过 |
| 生产配置同步、费用池/其他 Profile、迁移、两端产品接入与验收 | 待施工 |

旧 0.1 检查：110 项通过 / 0 失败 / 4 项不可验证；此数字不代表 v2。
v2 新增实际检查及限制见 [施工与验证报告](./reports/0005-v2-施工与验证.md)。
本轮集成测试范围见 [需求与施工单](./docs/SDK集成测试需求与施工单.md)，执行方式见 [子项目说明](./Coding/BSV8_VaultLinkProtocol/integration/README.md)。
独立 SDK 的当前目标板 USB 集成已验证；完整产品兼容、PIN/屏幕/实体按键、电气断电专项及独立安全审计尚未验收。
详见 [验收报告](./reports/0004-V0V1-验收报告.md)。

新版契约：[核心协议](./spec/v2/01-核心协议.md)、[支付与持久状态](./spec/v2/02-支付与持久状态.md)、[断电重连](./spec/v2/03-断电与重连.md)、[SDK](./Coding/BSV8_VaultLinkProtocol/README.md)。

## 文档入口

- [需求](./docs/需求.md)：项目边界、Core/Profile、安全与授权、SDK、迁移及验收要求。
- [施工单](./docs/施工单.md)：V0–V8 及本轮 B0–B3 修订任务、依赖与验收门禁。
- [USB 最简交互与外部说明查询设计](./docs/USB最简交互与外部说明查询设计.md)：保留 USB 简化，原设备外部说明已撤销。

- [密钥后端最小职责需求](./docs/密钥后端最小职责需求.md)与[施工单](./docs/密钥后端最小职责施工单.md)：当前三方边界、费用池冻结及 MIN 验收。

## 历史 0.1 规范（`spec/core` 等）

| 路径 | 内容 |
| --- | --- |
| [spec/core/01-术语与版本.md](./spec/core/01-术语与版本.md) | 字段表、溢出与重启规则、分层、版本矩阵、包名（拟定） |
| [spec/core/02-编码.md](./spec/core/02-编码.md) | `VLP-CBOR-1`：键序、整数、上限、嵌套、域标签与摘要构造 |
| [spec/core/03-帧与消息.md](./spec/core/03-帧与消息.md) | 帧格式、限额与容量实测、记录加密、事件、超时 |
| [spec/core/04-握手与链路.md](./spec/core/04-握手与链路.md) | 版本协商、transcript、方向密钥、配对码、持有权证明 |
| [spec/core/05-承诺与授权.md](./spec/core/05-承诺与授权.md) | `requestCommitment` 与 `grantScope` 的分离、决定状态机、限额 |
| [spec/core/06-请求状态与事件.md](./spec/core/06-请求状态与事件.md) | 状态机、查询、防重放、事件、取消 |
| [spec/core/07-错误码.md](./spec/core/07-错误码.md) | 14 类错误数字码与重试规则 |
| [spec/security/01-密码套件.md](./spec/security/01-密码套件.md) | `vlp-suite-v1` 原语、域标签清单、签名参数、自检要求 |
| [spec/transports/01-usb-serial.md](./spec/transports/01-usb-serial.md) | USB Serial 契约、0.1 仅单帧、失活清理 |
| [spec/profiles/](./spec/profiles/00-通用约定.md) | Identity / BSV P2PKH / Channel / Local Secret / Content / Migration / Evidence |

## 决策记录（`decisions/`）

| 文件 | 内容 |
| --- | --- |
| [0001-来源审计.md](./decisions/0001-来源审计.md) | 两端准确 commit、未提交改动的内容哈希、SDK 来源与版本 |
| [0002-差异清单.md](./decisions/0002-差异清单.md) | 7 阻断 / 15 须冻结 / 8 文档矛盾 / 5 外部待定 / 6 覆盖缺口 |
| [0003-冻结决策.md](./decisions/0003-冻结决策.md) | 22 条冻结决策及其理由与被否决方案 |

## 工具（`tools/`、`conformance/`、`schemas/`）

| 路径 | 作用 |
| --- | --- |
| `tools/refgen/vlp_ref.py` | **路径 A**：独立参照实现，只用 Python 标准库 |
| `tools/refgen/generate_vectors.py` | 生成 `test-vectors/` 与 manifest |
| `tools/refgen/selfcheck.py` | 路径 A 自检（不依赖向量，避免循环论证） |
| `tools/refgen/crosscheck.py` | 路径 A 独立复核向量期望值 |
| `conformance/run.js` | **路径 B**：Node 自实现编解码 + Node 内置成熟密码实现实际执行 |
| `schemas/*.schema.json` | 机器可读结构（**只检查结构，不代替语义验证**） |
| `test-vectors/` | 公开向量与 manifest（记录来源版本、材料哈希） |

## 复现

```bash
./scripts/verify.sh            # 生成向量 → 自检 → 交叉复核 → 合规运行
./scripts/verify.sh --check    # 只校验；向量过期即失败
node conformance/run.js --json # 机器可读报告
```

以上为旧 0.1 检查，依赖 Python 3 标准库与 Node.js 18+。

v2 首次安装与复现：

```sh
cd Coding/BSV8_VaultLinkProtocol
npm ci --ignore-scripts
cd ../..
./scripts/verify-sdk.sh
```

v2 依赖 Node 22+、Python 3、C++17 编译器及 lockfile 固定的密码/构建依赖。安装需访问 npm，验证不访问网络。

## 与既有仓库的关系

Rockey 的协议层（`src/proto`、`src/policy`、`src/ops`）是本规范的**审计输入**，
不是权威来源。审计发现的 7 项阻断缺陷中，规范已给出正确规则并由参照实现落实；
Rockey 固件需升级后才可声明兼容，**不提供旧 wire 的隐藏兼容分支**。
修复 Rockey 与 Keymaster 属跨仓库任务，需另行授权，本仓库不自动执行。

本仓库**不**承担 Keymaster 的数据库/插件/广播与 Rockey 的 GPIO/屏幕/PIN/固件职责。
`Evidence` Profile 已退出当前设备范围，**不出现在已支持集合**。

仓库现有许可见 [LICENSE](./LICENSE)。规范/SDK/资源的许可标识与第三方清单在发布时准确记录。
