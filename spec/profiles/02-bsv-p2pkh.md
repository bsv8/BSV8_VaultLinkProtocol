# BSV P2PKH Profile

> VLP 0.1 Draft · profileId `bsv.p2pkh` · profileVersion `0.1`
> 决策见 [D-016](../../decisions/0003-冻结决策.md)（单帧限额）。

## 1. 范围

原始 BSV 交易的输入签署。设备**重建交易并自算 sighash**，
核验前序证据、输入归属、全部输出、找零与费用。

| 项 | 值 |
| --- | --- |
| 脚本类型 | **仅**标准 P2PKH（25 字节 `76 A9 14 <20> 88 AC`） |
| 网络 | **仅** BSV mainnet（version `0x00000000`） |
| sighash | `SIGHASH_ALL|SIGHASH_FORKID = 0x41`，BIP143 |
| 金额单位 | satoshi，u64 |
| 上限 | 输入 ≤ **4**，输出 ≤ **6**，rawTx ≤ **640** 字节（受单帧限额约束，见 §8） |

不支持 P2SH、多签、OP_RETURN、裸 P2PK、其它网络或其它 sighash 类型。
**未知脚本明确拒绝**，不降级。

## 2. 操作 `tx.p2pkh-sign`

| 序 | 键 | 键长 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- | --- | --- |
| 1 | `op` | 2 | text | 是 | `"tx.p2pkh-sign"` |
| 2 | `opVersion` | 9 | u32 | 是 | = 1 |
| 3 | `rawTx` | 5 | bytes | **是** | 完整未签名交易，1–**640** 字节 |
| 4 | `network` | 7 | u32 | **是** | 必须 `0` |
| 5 | `prevouts` | 8 | array | **是** | 1–4 元素，每元素为 map |
| 6 | `inputIndex` | 10 | u32 | **是** | 待签输入下标，< 输入数 |

键序：`op(2) < rawTx(5) < network(7) < prevouts(8) < opVersion(9) < inputIndex(10)`。

> `inputIndex` **必填**。现有实现中它是可选的，且因嵌套 map 解析缺陷
> （[0002](../../decisions/0002-差异清单.md) §1 B1），携带 `prevouts` 时
> 必然解析失败，省略时静默签第 0 个输入。VLP 要求必填且修复容器状态。

### 2.1 `prevouts` 元素

map(5)，键序：

| 序 | 键 | 键长 | 类型 | 约束 |
| --- | --- | --- | --- | --- |
| 1 | `txid` | 4 | bytes | 恰好 32，**与 `rawTx` 中的字节序相同** |
| 2 | `vout` | 4 | u32 | 输出下标 |
| 3 | `proven` | 6 | bool | **仅为主机声称**，见 §5.3 |
| 4 | `script` | 6 | bytes | 恰好 25 字节 P2PKH |
| 5 | `satoshis` | 8 | u64 | 该输出金额 |

键序：`txid(4) = vout(4) < proven(6) = script(6) < satoshis(8)`。
同为 4 时 `txid` < `vout`（`t` < `v`）；同为 6 时 `proven` < `script`。

## 3. sighash 构造

BIP143，`SHA256d` = SHA256(SHA256(x))。

### 3.1 三个哈希

```
hashPrevouts = SHA256d( ‖ over all inputs:  txid(32) ‖ vout(u32 LE) )
hashSequence = SHA256d( ‖ over all inputs:  nSequence(u32 LE) )
hashOutputs  = SHA256d( ‖ over all outputs: satoshis(u64 LE)
                                            ‖ varint(scriptLen) ‖ script )
```

### 3.2 前像

```
nVersion        u32 LE   4
hashPrevouts    32
hashSequence    32
outpoint.txid   32          与 rawTx 中的字节序相同
outpoint.vout   u32 LE      4
scriptCodeLen   varint      1（脚本 < 0xFD 时）
scriptCode      25          完整 P2PKH 脚本
amount          u64 LE      8    来自 prevout 证据，非交易自身
nSequence       u32 LE      4    待签输入的完整 32 位 sequence
hashOutputs     32
nLockTime       u32 LE      4
nHashType       u32 LE      4    常量 0x00000041

sighash = SHA256d(preimage)
```

P2PKH 输入的前像长度为 **182 字节**。

> 现有实现中 `totalOut` 累加无溢出检查
> （[0002](../../decisions/0002-差异清单.md) §2 S12）。VLP 要求累加前检查溢出。

## 4. 设备验证顺序

| 序 | 检查 | 失败 |
| --- | --- | --- |
| 1 | `rawTx` 可解析且无尾随字节 | `invalid-request` |
| 2 | `network == 0` | `invalid-request` |
| 3 | `inputIndex < 输入数` | `invalid-request` |
| 4 | **每个**输入都有匹配的 `(vout, txid)` 前序证据 | `invalid-request` |
| 5 | 每个前序脚本恰为 25 字节标准 P2PKH | `invalid-request` |
| 6 | `totalIn ≥ totalOut`（否则费用为负） | `invalid-request` |
| 7 | 待签输入的 hash160 == `RIPEMD160(SHA256(业务公钥))` | `wrong-key` |
| 8 | 每个输出脚本均为 P2PKH | `invalid-request` |
| 9 | 至少一个付款输出（非找零） | `invalid-request` |
| 10 | 找零输出存在且 hash160 属于本 Key | `invalid-request` |

**第 7 步是防"签别人的 UTXO"的唯一检查**，必须严格执行。

## 5. 审核内容

设备从交易**自行重建**收款明细，主机提供的说明只是辅助内容。

### 5.1 必含

| 项 | 来源 |
| --- | --- |
| 业务公钥**全文**（不截断） | 设备 |
| 找零地址（Base58Check） | 设备自算 |
| **全部**输出：金额 + 地址（付款与找零分别标注） | 设备自算 |
| 总输入、总输出、**费用** | 设备自算 |
| 网络 | 设备验证 |

### 5.2 不含的权限

审核对象必须明确列出：本次**不**授予持续授权（§6），
**不**修改找零规则，**不**授予任何其它交易的签署权限。

### 5.3 证据状态

| 事实 | 表述 |
| --- | --- |
| 前序字节已核验 | 是（设备自己解析比对） |
| 链上已确认 | **未知**——`proven` 仅为主机声称 |
| 输出未被花费 | **未知** |

**链上事实缺乏证明时如实标注。** `proven=true` 不能升级为链上已确认事实，
`proven` 只影响风险提示的措辞，不放宽任何验证。

## 6. grantScope

**BSV P2PKH 不支持持续授权。** 每笔交易都重新确认。

理由：需求 §6 要求 Channel 持续授权不得覆盖支付；且把交易签署纳入持续授权
等于让一次授权外溢到任意金额的任意收款方。金额限额的持续授权在本 Profile
**不提供**。

## 7. 结果

map(4)，键序：

| 序 | 键 | 键长 | 类型 |
| --- | --- | --- | --- |
| 1 | `sighash` | 7 | bytes 32（设备自算，供主机核对） |
| 2 | `publicKey` | 9 | bytes 33 |
| 3 | `signature` | 9 | bytes，strict DER |
| 4 | `sighashType` | 11 | u32 = 0x41 |

脚本签名由**主机**按既有规则组装：
`varint(len(der‖0x41)) ‖ der ‖ 0x41 ‖ varint(33) ‖ compressedPub`。

VLP **不**定义组装后的完整交易格式——那是 BSV 既有 wire，不属本规范。

## 7.1 容量验证（实测）

编码后请求体尺寸由 `tools/refgen` 测得，权威副本在
`test-vectors/limits/frame-capacity.json`：

| 样本 | 明文字节 | 单帧可容纳 |
| --- | ---: | --- |
| 1 输入 2 输出 | 289 | 是 |
| 4 输入 6 输出（上限） | 855 | 是 |

上限样本 855 字节已逼近 896 的单帧上限，这是收敛到 4 输入 / 6 输出的原因。
更大的交易**必须**走后续传输规格的分片（[D-016](../../decisions/0003-冻结决策.md)），
0.1 明确拒绝。

## 8. 承诺覆盖对象

```
commitObject = {
  inputIndex     u32
  network        u32
  rawTx          bytes
  prevouts       array of { txid, vout, satoshis, script }
}
```

**覆盖**：实际被签的完整交易字节、网络、待签输入下标、
**每一个**前序证据（含金额与脚本）。

`proven` **不进入承诺**——它不影响签名结果，只是主机声称；
把它纳入承诺会让主机能通过改 `proven` 影响承诺值，而签名字节不变。
主机可随意声称 `proven`，设备在审核对象中标为"未知"。

设备必须按 §3 从 `commitObject` 独立重算 sighash 并**与自算值比对**，
不一致 → `invalid-request`。

## 9. 预览与估费不签名

| 规则 | 内容 |
| --- | --- |
| 预览 | 主机可构造未签名交易并展示，**不请求本 Profile 签署** |
| 估费 | 只用未签名交易的长度计算，**不产生签名** |
| 显示 | 收款明细必须来自**实际将被签的交易**，不是主机的另一份副本 |
| 禁止 | 反复要求用户授权或产生可广播签名以测量 |

> Keymaster 当前在费用求解器中调用 `signRawTx` 生成真实签名以测量字节长度
> ——[0002](../../decisions/0002-差异清单.md) §4 X1。这是接入时必须重构的产品侧问题。

## 10. 负向向量（必须确定失败）

| 情形 | 期望 |
| --- | --- |
| 换收款方但保留旧承诺 | 承诺不匹配 → `invalid-request` |
| 换 `inputIndex` 保留旧承诺 | 同上 |
| 换金额（satoshis） | 同上 |
| 换网络为非 0 | `invalid-request` |
| 前序 hash160 不是本 Key | `wrong-key` |
| 缺前序证据 | `invalid-request` |
| 非 P2PKH 输出脚本 | `invalid-request` |
| 找零不属于本 Key | `invalid-request` |
| 无付款输出 | `invalid-request` |
| `totalOut > totalIn` | `invalid-request` |
| 省略 `inputIndex` | `invalid-request` |
| 尾随字节的 `rawTx` | `invalid-request` |
| 金额 u64 溢出 | `invalid-request` |

## 11. 与 Keymaster 软件路径兼容

BSV P2PKH 的 sighash、序列化与 scriptSig 组装规则**完全沿用**既有实现
（见 `decisions/0001-来源审计.md` §4.2）。VLP 只替换"谁签名、按什么授权"
这条路径，**不改变**签名字节规则。

兼容含义：**验签兼容**，不要求随机签名字节完全一致
（ECDSA nonce 是确定性的 RFC 6979，同输入应一致，但兼容判据是验签通过）。