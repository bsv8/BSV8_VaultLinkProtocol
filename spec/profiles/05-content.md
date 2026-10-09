# Content Attestation Profile

> VLP 0.1 Draft · profileId `content` · profileVersion `0.1`

## 1. 语义边界（必须准确表述）

| 是 | 不是 |
| --- | --- |
| 设备对**主机计算的文件摘要**与声明用途签名 | 设备**读过**该文件 |
| 一份可验证的声明 | 任何形式的"内容已在设备上验证" |
| 与业务对象分离的用途声明 | 交易/付款授权 |

**这不是设备读取文件的证明。** 设备只签它被告知的摘要与用途。

本 Profile **不授权交易**，固定模板**不**产生任何付款能力。

## 2. 操作 `content.attest-digest`

| 序 | 键 | 键长 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- | --- | --- |
| 1 | `op` | 2 | text | 是 | `"content.attest-digest"` |
| 2 | `digestHex` | 9 | text | **是** | 小写 hex，解码**恰好 32** 字节 |
| 3 | `fileName` | 8 | text | 是 | 1–47 字节，良构 UTF-8 |
| 4 | `opVersion` | 9 | u32 | 是 | = 1 |
| 5 | `purpose` | 7 | text | **是** | 1–63 字节 |

键序（长度优先再字节序）：`op(2) < purpose(7) < fileName(8) < digestHex(9) < opVersion(9)`。
`digestHex` 与 `opVersion` 长度相同，按字节序 `d` < `o`，故 `digestHex` 在前。

## 3. 被签声明

```
statementDigest = SHA256d(
    "vlp:content:v1"      UTF-8, 14 字节, 无 NUL
 || 0x00
 || purpose              UTF-8
 || 0x00
 || digestHex            小写 hex 文本, 64 字符
)
```

注意：**签的是主机给出的 hex 文本本身**（规范化后小写），不是解码后的字节。
这是与既有实现的兼容约定，主机与设备必须用同一形式。

`SHA256d` = SHA256(SHA256(x))。

## 4. 结果

map(3)，键序：

| 序 | 键 | 键长 | 类型 |
| --- | --- | --- | --- |
| 1 | `publicKey` | 9 | bytes 33 |
| 2 | `signature` | 9 | bytes，strict DER |
| 3 | `statementDigest` | 15 | bytes 32 |

## 5. 承诺覆盖对象

```
commitObject = {
  digestHex    text
  fileName     text
  purpose      text
}
```

**覆盖**：被签的摘要、文件名与用途——三者都是显示内容，必须进承诺。

> 现有实现的授权匹配键用的是**主机声明摘要的前 16 字节**，
> 而显示的是设备自算的 `statementDigest`——两者不是同一个值
> ——[0002](../../decisions/0002-差异清单.md) §5.5。
> VLP 统一：承诺覆盖 hex 全文，设备按 §3 重算并比对。

## 6. grantScope

**Content 不支持持续授权。** 每次重新确认。

## 7. 审核内容

设备生成的模板必须显示：

| 项 | 来源状态 |
| --- | --- |
| 完整 64 字符摘要 | 设备格式化 |
| 文件名 | 主机提供，标注为"主机声称" |
| 用途 | 主机提供，标注为"主机声称" |
| **"设备未读取该文件"** | 设备生成的固定提示 |

`fileName` 与 `purpose` 是**主机提供**的，审核对象必须标明来源状态，
不得让用户误以为是设备验证过的。

## 8. 负向向量（必须确定失败）

| 情形 | 期望 |
| --- | --- |
| 换 `purpose` 保留旧承诺 | `invalid-request` |
| 换 `fileName` 保留旧承诺 | 同上 |
| 换 `digestHex` 保留旧承诺 | 同上 |
| `digestHex` 解码 ≠ 32 字节 | `invalid-request` |
| 大写 hex 输入（若 Profile 要求小写） | 规范化或拒绝，二选一并写死 |
| 域标签错误 | 验签失败 |
| 空 `purpose` / 空 `fileName` | `invalid-request` |