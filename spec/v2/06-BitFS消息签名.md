# BitFS 消息签名 Profile（v2 草案）

本 Profile 接通 Keymaster 已使用的 go-bitfs 0.3.2 消息签名，不修改 BitFS wire。设备只解释固定的签名类型、关联对象和基础金额；业务关系、内容和信用解释归 Keymaster。

操作 `bitfs.wire-sign`，Profile `bitfs-wire-document`，版本 1。请求 body 严格为 `{kind:uint, document:bstr}`，document 是 SDK 实际构造的 deterministic CBOR 子文档原文，最大 16384 字节，最多 256 个 CBOR 节点。不得传入摘要代替文档；设备自行重建 `SHA256(CBOR(["bitfs/wire-signature", 1, kind, document]))`。承诺绑定完整 body。返回 `{publicKey:bstr33, signature:bstr}`，签名为 strict low-S DER，不带交易 sighash 标志。

仅允许已有消息签名 Kind：1 报价、5 付款授权、6 内容交付、8 仲裁申请、9 仲裁回执、10 内容取回请求、11 内容取回结果。Kind 2/3/7/12 的交易签名继续走费用池专用 Profile；Kind 4/13 不需要消息签名。未知 Kind 拒绝，无通用摘要回退。

文档按 go-bitfs 0.3.2 的固定数组解析，不能仅显示调用方提供的标签。嵌套公钥须为有效的压缩 secp256k1 公钥；标识/哈希按各 Kind 检查长度和禁止零哨兵；序号、截止时间、列表数量及分支必须满足原协议。Kind 8 须验证三方池脚本、退款模板的角色输出、付款序号和买方 Kind 5 授权签名，并要求当前设备为卖方。其它 Kind 的角色/证据关系由 Keymaster 已有工作流核验；不能把消息签名当作通过了链上金额授权。

设备显示实际 Kind、文档哈希，以及文档中已有的对方公钥、对象 ID、累计付款/报价/仲裁金额、序号或有效期。普通消息签名经设备一次性同意或否决，不共享 Channel 的持续授权。

**Kind 5 是付款授权，不能作为普通消息绕过金额核心。** `bitfs.wire-sign` 收到 Kind 5 必须拒绝 `payment-context-required`。实际工作流使用 `tx.feepool-bitfs-authorize`，Profile `bsv-feepool-bitfs-authorization`，body 为 BitFS payer/state 交易签名的原字段，再增加 `authorization:{document:bstr,refundTemplate:bstr}`。承诺仍包括设备独立计算的 amount。设备核验完整 FundingTx、退款模板和目标未签交易，要求文档的退款 ID 等于模板 double-SHA256、序号等于目标交易序号且高于模板、累计卖方金额等于实际目标输出，仲裁方输出为零。模板对外金额必须为零，目标交易 nLockTime 为零。不能把宿主声明金额当成额度依据。

额度按实际池 outpoint 的持久 paid 基线计算新增量，**在产生 Kind 5 签名前预占并持久化**。低于单笔/App 本会话累计上限自动签；超额软端弹窗/硬端按钮确认，同原有提高本会话额度规则。返回的 signatures 数组仅含 Kind 5 strict low-S DER，不添加 0x41。后续 Kind 7 签署已授权的相同累计金额，新增量为零，不重复扣额度或重复弹出金额确认；其完整交易和实际前序证据仍须独立核验。签名结果未知保留预占及池基线。SDK `prepareBuyerContentRequest` 将自身已核验的 fundingTransactionRaw、refundTemplateRaw 和构造的 unsignedTransactionRaw 携带到 Signer，不改变线上消息。

Keymaster 的 Signer 适配必须收到 SDK 构造的 `documentCBOR` 副本，并重新计算摘要与 SDK 的 digest 比对。软钱包保留原有实际签名行为；硬钱包只调用本语义 Profile。SDK patch 仅增加原文携带字段，不改变域、算法、签名或线上报文。

## 卖方开池预签（Draft 0x22d）

operation `tx.feepool-bitfs-opening`，profile `bsv-feepool-bitfs-opening` v1。沿用付款命令字段 rawTx、prevTransactions、channelId、paymentId、sessionId、stage、role，额外字段 `openingRequest:bstr` 是 exact Kind 2 原文；stage=state、role=cosigner、prevTransactions 必须为空，不能与 authorization 共存。它只支持当前设备为卖方的 Kind 2→3 阶段。

Kind 2 是既有 go-bitfs 的 8 项 CBOR 数组 `[1,2,refundRaw,buyerPub,sellerPub,arbiterPub,feeRate,buyerRefundSignature]`。解析器独立检查有效且不同的三方公钥、当前卖方公钥、rawTx 与 refundRaw 完全相等。退款模板 version=1、一个 unsigned input、vout=0、sequence=2、三个固定角色 P2PKH 输出，卖方/仲裁方金额为零。

与 keymaster-multisig-pool v4 的真实构造器一致，假设两份最大交易签名后的序列化大小为 unsignedRaw.length + 149，矿工费 ceil(size×feeRate/1000)。输入池金额仅由买方退款金额加此矿工费推导；运算与金额限制在 JavaScript 安全整数内。设备从三方公钥重建 2-of-3 脚本，重新计算 ForkID|ALL 摘要，并核验买方退款签名为严格 low-S DER || 0x41。主机不能传输入金额、伪造前序交易或用缺失资金原文跳过验证。

该操作沿用已注册 `feepool.bitfs.cosigner` 渠道和钱包账本，自己资金消费金额为 0，按现有额度策略执行；结果仍为 signatures 数组（DER || 0x41）。签名之前持久记录支付请求，未知结果保持占用。完整 funding 在既有 Kind 4 阶段由业务 SDK 核验，不宣称预签时已验证尚未交付的 funding。

go-bitfs 的 prepareSellerPresign 在验证实际 Kind 2 后向 Signer 传 openingRequestRaw；Keymaster 的费用池适配器核验完整对象和真实摘要，通过钱包核心转发。没有开放原始摘要签名作为退路。
