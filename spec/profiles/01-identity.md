# Identity Profile

> VLP 0.1 Draft · profileId `identity` · profileVersion `0.1`
> 决策见 [D-018](../../decisions/0003-冻结决策.md)。

## 1. 范围

当前唯一的 secp256k1 业务身份。首版**不**增加钱包列表、多 Key 管理或
密钥派生路径体系（需求 §1）。

**设备不提供 `signHash` 或任意摘要签名接口。** 本 Profile 的每种操作都有
固定的、域隔离的被签声明构造。

## 2. 操作

### 2.1 `identity.prove`

| 序 | 键 | 键长 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- | --- | --- |
| 1 | `op` | 2 | text | 是 | `"identity.prove"` |
| 2 | `opVersion` | 9 | u32 | 是 | = 1 |
| 3 | `challenge` | 9 | bytes | **是** | 恰好 32 |
| 4 | `purpose` | 7 | text | **是** | 1–63 字节，良构 UTF-8 |

键序（长度优先再字节序）：`op(2) < purpose(7) < challenge(9) < opVersion(9)`。
`challenge` 与 `opVersion` 长度相同，按字节序 `c` < `o`，故 `challenge` 在前。

> `challenge` 与 `purpose` 均**必填**。现有实现缺失时仍视为有效请求
> （省略 `challenge` 会签 32 个零字节的声明）
> ——[0002](../../decisions/0002-差异清单.md) §2 S3。VLP 要求必填。

### 2.2 `identity.authorize`

字段与 `identity.prove` **完全相同**，仅 `op` 值不同。
用于身份/意图授权：绑定用途、对象与会话。

## 3. 被签声明

```
statementDigest = SHA256d(
    "vlp:identity:<class>:v1"     class ∈ {prove, authorize}，无 NUL
 || 0x00
 || publicKey                    33
 || sessionId                    u32 大端
 || sessionEpoch                 u8
 || challenge                    32
 || 0x00
 || purpose                      UTF-8
)
```

| 项 | 字节数 |
| --- | --- |
| `vlp:identity:prove:v1` | 21 |
| `vlp:identity:authorize:v1` | 25 |

`SHA256d` = SHA256(SHA256(x))。

**调用方提供 32 字节挑战；设备不隐式二次 hash。** 签名输入就是上述 32 字节摘要。

## 4. 结果

`identity.prove` / `identity.authorize` — map(4)，键序：

| 序 | 键 | 键长 | 类型 |
| --- | --- | --- | --- |
| 1 | `challenge` | 9 | bytes 32（原样回显） |
| 2 | `publicKey` | 9 | bytes 33 |
| 3 | `signature` | 9 | bytes，strict DER 或 compact |
| 4 | `signatureFormat` | 15 | text：`der-strict-lows` 或 `compact-lows` |

> `signatureFormat` 键长为 **15**（现有冻结文档写 25）
> ——[0002](../../decisions/0002-差异清单.md) §2 S6。

## 5. 承诺覆盖对象

```
commitObject = {
  challenge      bytes 32
  purpose        text
}
```

**覆盖**：实际被签的挑战 + 显示的用途。
**不覆盖**：`publicKey`（设备自己知道）、会话元数据（链路层绑定）。

设备按 §3 独立重算 `statementDigest` 并签它；主机可完全重算并验签。

## 6. grantScope

**Identity 不支持持续授权。** 每次都重新确认。

理由：身份/意图授权的语义就是"这一次、这个用途"。把它变成可复用范围
等于让一个用途的授权外溢到其它用途。

## 7. 签名格式

| 格式 | 值 | 说明 |
| --- | --- | --- |
| strict DER | `der-strict-lows` | 默认，8–72 字节 |
| compact | `compact-lows` | `r ‖ s` 64 字节，**不带恢复 ID** |

两者均 **low-S 归一化**。DER 只允许短形式长度（见
[01-密码套件](../security/01-密码套件.md) §6.1）。

**不得**隐式二次 hash；**不得**把 compact 当作带恢复 ID 的格式。

## 8. 负向向量（必须确定失败）

| 情形 | 期望 |
| --- | --- |
| 省略 `challenge` | `invalid-request` |
| 省略 `purpose` | `invalid-request` |
| `challenge` 长度 ≠ 32 | `invalid-request` |
| 跨会话用旧 `sessionId` 的签名 | `wrong-key` 或 `invalid-request` |
| 换 `purpose` 后重放旧声明 | 验签失败 |
| 高 S 签名 | strict DER 校验拒绝 |
| 非最短 DER | strict DER 校验拒绝 |
| 域标签错误（用 `prove` 标签验 `authorize` 声明） | 验签失败 |

## 9. 持有权证明（链路层）

持有权证明属 Core，不属本 Profile 运算；其构造见
[04-握手与链路](../core/04-握手与链路.md) §5。

**持有权证明与身份声明是两种不同的 schema**，分别绑定用途/对象/会话，
**不得**互相替代或复用域标签。