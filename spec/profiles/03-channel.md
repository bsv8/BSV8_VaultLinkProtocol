# Channel Profile

> VLP 0.1 Draft · profileId `channel` · profileVersion `0.1`
> 决策见 [D-014](../../decisions/0003-冻结决策.md)。

## 1. 规范权威：`bsv8-channel-protocol@0.6.0`

**本 Profile 的 wire 完全以 `bsv8-channel-protocol@0.6.0` 为准**，
逐字节引用其规则，**不重新发明、不改写**。摘要规则、scope 字符串、
密钥协商、编码、错误码全部照搬该版本。

> 现有 Rockey 的 `rockey:channel:*` 摘要是**不同协议**，
> 与本 Profile **完全不兼容**（不只是密钥协商）
> ——[0002](../../decisions/0002-差异清单.md) §3 D4。
> VLP 不维护隐藏兼容分支；Rockey 现有 Channel 实现需整体重写。

## 2. 冻结的 BSV8 wire 规则

| 项 | 规则 |
| --- | --- |
| 公钥 | 66 字符**小写** hex，压缩 secp256k1 点 |
| 签名 | strict DER 的**无填充 base64url**，8–72 字节，low-S，规范 DER 重编码须一致 |
| `message_id` / `session_id` | 32 字节 → 无填充 base64url（43 字符） |
| JCS | RFC 8785（键按 UTF-16 码元排序） |

### 2.1 摘要公式

| 操作 | 摘要 |
| --- | --- |
| `public-message` | `SHA256(JCS({scope:"bsv8.public-message.v1", channel, from_public_key, message}))` |
| `hash-request` | 同上，`scope` 同值，`channel` 强制为 `bsv8.hash.request.v1` |
| `private-message` | `SHA256(JCS({scope:"bsv8.private-message.v1", channel, from_public_key, message}))` |

wire 消息体省略 `channel`（`public-message`/`hash-request`）或同时省略
`channel` 与 `from_public_key`（`private-message`）。

寿命上限：`public`/`hash-request` ≤ 10 分钟；
`private` 按子协议——Ping/Pong 60 000 ms、WebRTC 120 000 ms、
app-message/默认 86 400 000 ms。

### 2.2 私密信封 seal/open

```
salt       = 32 字节随机
nonce      = 12 字节随机
shared     = ECDH_x(私钥, 对端公钥)        压缩点 X 坐标, 32 字节
info       = JCS({scope:"bsv8.inbox.envelope.v1", channel, from_public_key})
kdf_salt   = base64url(salt)               43 字符
nonce_text = base64url(nonce)              16 字符
aad        = JCS({channel, envelope_version:1, from_public_key, kdf_salt, nonce})
key        = HKDF-SHA256(ikm=shared, salt=salt, info=info, L=32)
ciphertext = AES-256-GCM(key, nonce, aad).encrypt(plaintext)   密文 ‖ 16 字节 tag
```

信封字段：`{channel, envelope_version, from_public_key, kdf_salt, nonce, ciphertext}`。
`envelope_version` 必须 `= 1`。多一个字段即拒绝。

## 3. 操作

| 操作 | 说明 |
| --- | --- |
| `channel.public-message` | 公共消息签名 |
| `channel.hash-request` | Hash 请求签名 |
| `channel.private-message` | 私密消息签名 |
| `channel.seal` | 密封私密信封 |
| `channel.open` | 解封私密信封 |

各操作的字段集与键序见 `schemas/profile-channel.json`；
所有字段必须必填（现有实现中 `seal` 忽略 `nonce`、`open` 忽略 `message`，
VLP 不接受这种不对称——[0002](../../decisions/0002-差异清单.md) §2 S9）。

`protocol` 名必须**已登记**；未登记直接拒绝，不降级为"无协议"。
现有实现的登记名：`messaging`、`payment-request`、`auth`、`storage`。

## 4. 互操作要求

| 要求 | 内容 |
| --- | --- |
| 双向 | **不同身份 A→B 与 B→A 真实往返**必须通过 |
| 禁止 | 不用同设备自封自解替代互通 |
| 判据 | 验签通过 + 双向解封成功；**不要求**随机密文字节完全一致 |

这是 V5 门禁项，不达标则 Channel Profile **不得**列入已支持集合。

## 5. grantScope

**Channel 是唯一支持持续授权的业务 Profile**，但范围严格受限。

```
grantScope = {
  peerPublicKey,    bytes 33      对端公钥（seal→recipient，open→sender）
  protocolId,       u8            已登记协议
  direction,        u8            seal=outbound，其余=inbound
  sessionId,        u32
  sessionEpoch,     u8
}
```

| 规则 | 内容 |
| --- | --- |
| 对端交叉 | `seal` 只接受 `recipientPub`，`open` 只接受 `senderPub`；交叉填写直接拒绝 |
| 消息摘要 | **不进入 grantScope**（否则每条消息都要重新确认） |
| 逐请求绑定 | 每条消息仍由**独立** `requestCommitment` 绑定 |
| 支付/导出/擦除 | **不在** Channel 持续授权覆盖范围内 |

**没有语义解析器的消息不自动获得宽范围授权**——若设备无法把消息解析为
已知 Profile 对象，则不产生 `grantScope`，必须逐次确认。

## 6. 承诺覆盖对象

```
commitObject = {
  channel           text
  protocol          text
  recipient/sender  bytes 33
  message/bytes     实际被签或被封的字节
}
```

**覆盖**：实际消息字节（或密文）、协议名、对端公钥、频道。
设备按 §2 独立重算摘要并**比对**；不符 → `invalid-request`。

## 7. 负向向量（必须确定失败）

| 情形 | 期望 |
| --- | --- |
| 换对端公钥保留旧承诺 | `invalid-request` |
| 换协议名 | `invalid-request` |
| 换消息字节 | `invalid-request` |
| `seal` 填 `senderPub` / `open` 填 `recipientPub` | `invalid-request` |
| 未登记协议名 | `invalid-request` |
| 跨会话用旧 grantScope | 需重新确认 |
| 换方向（in↔out）沿用持续允许 | 需重新确认 |
| 换对端沿用持续允许 | 需重新确认 |
| 尝试用 Channel 持续授权签支付 | `unsupported`（支付不属本 Profile） |
| 信封缺字段或多字段 | `invalid-request` |
| 寿命超限 | `invalid-request` |
| 消息超过单帧限额 | `invalid-request` |

## 8. 容量限制

Channel 消息与信封受 VLP 0.1 单帧上限约束
（[03-帧与消息](../core/03-帧与消息.md) §3、`D-016`）。
超限**明确拒绝**，不静默截断。

BSV8 SDK 自身的 `MAX_JSON_BYTES = 1 048 000` 远大于 VLP 单帧上限，
因此 VLP 能承载的 Channel 消息是该上限的一个**子集**。
实际边界由 `test-vectors/limits/frame-capacity.json` 给出，
各操作的消息长度上限按该文件收敛。

**不声称**可传任意长度消息。