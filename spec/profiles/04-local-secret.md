# Local Secret Profile

> VLP 0.1 Draft · profileId `local-secret` · profileVersion `0.1`
> 信封 `version` 仍为 **`3`**（v3 兼容）· 决策见
> [D-015](../../decisions/0003-冻结决策.md)。

## 1. 兼容目标

**必须能用旧软件（Keymaster）生成的 v3 密文解封，且旧密文继续可用。**
本 Profile 逐字节保持既有配方，不改任何字节。

## 2. 冻结配方（逐字节）

```
ikm   = 32 字节身份私钥（原值，不哈希、不编码、不加盐）
salt  = "keymaster.vault.local-secret.v3"              31 字节 ASCII
info  = UTF8(小写压缩公钥 hex, 66 字符) ‖ 0x00 ‖ UTF8(scope)
key   = HKDF-SHA256(ikm=ikm, salt=salt, info=info, L=32)    → AES-256-GCM 密钥

aad   = UTF8("keymaster:local-secret:v3|") ‖ UTF8(scope) ‖ 0x00 ‖ salt(16)
```

| 项 | 值 |
| --- | --- |
| HKDF salt | **常量** `keymaster.vault.local-secret.v3`（不是每条随机） |
| HKDF info | `小写公钥hex(66) ‖ 0x00 ‖ scope` |
| 信封 salt | 16 字节随机 |
| nonce | 12 字节随机 |
| AAD 前缀 | `keymaster:local-secret:v3|`（26 字节） |
| AAD 分隔 | scope 之后**单个** `0x00`，然后 16 字节 salt |

> **易错点**：16 字节信封 salt **只出现在 AAD 里**，**从不**作为 HKDF 的 salt。
> 把它挪进 HKDF salt 会解不开所有既有 v3 密文。

### 2.1 `scope` 约束

| 规则 | 内容 |
| --- | --- |
| 长度 | 1–**95** 字节（wire 上限） |
| 字符 | 每个字节 `> 0x1F` 且 `≠ 0x7F` |
| UTF-8 | 必须良构 |
| 不得为 0 | 空 scope 拒绝 |

> 现有实现声明 `kScopeMax=256` 但经 dispatch 实际只能到 95
> ——[0002](../../decisions/0002-差异清单.md) §2 S10。VLP 统一为 95，
> 消除"声明 256 实际 95"的分歧。

## 3. 操作

### 3.1 `local-secret.seal`

| 序 | 键 | 键长 | 类型 | 必填 | 约束 |
| --- | --- | --- | --- | --- | --- |
| 1 | `op` | 2 | text | 是 | `"local-secret.seal"` |
| 2 | `opVersion` | 9 | u32 | 是 | = 1 |
| 3 | `plaintext` | 9 | bytes | **是** | 1–**512** 字节 |
| 4 | `scope` | 5 | text | **是** | 见 §2.1 |

键序：`op(2) < scope(5) < opVersion(9) < plaintext(9)`。

### 3.2 `local-secret.open`

| 序 | 键 | 键长 | 类型 | 必填 |
| --- | --- | --- | --- | --- |
| 1 | `op` | 2 | text | 是 | `"local-secret.open"` |
| 2 | `scope` | 5 | text | 是 |
| 3 | `sealed` | 6 | map | **是**，恰好 5 对 |
| 4 | `opVersion` | 9 | u32 | 是 |

`sealed` 内层 map，键序：

| 序 | 键 | 键长 | 类型 | 约束 |
| --- | --- | --- | --- | --- |
| 1 | `saltHex` | 7 | text | 解码后**恰好 16** 字节 |
| 2 | `version` | 7 | u32 | **必须 = 3** |
| 3 | `nonceHex` | 8 | text | 解码后**恰好 12** 字节 |
| 4 | `keySource` | 9 | text | **必须 = `active-key-hkdf-v1`** |
| 5 | `ciphertextHex` | 13 | text | ≥ 16 字节（末 16 为 tag） |

> 对数必须**恰好 5**。现有实现曾接受 4 对，导致设备自己封的数据无法解开
> ——[0002](../../decisions/0002-差异清单.md) §5.3。VLP 严格要求。

## 4. 能力边界

| 规则 | 内容 |
| --- | --- |
| 不导出 | **不导出**长期派生密钥；`getPrivateKey` 不在导出面 |
| 内部派生 | HKDF 与解密全在设备内部完成 |
| scope 固定 | 派生密钥与 `scope` 强绑定，换 scope 不能解封 |
| 换 Key | 换业务 Key 后旧密文**不能**解封 |

## 5. 结果

### 5.1 `local-secret.seal`

map(5)，键序：

| 序 | 键 | 键长 | 类型 |
| --- | --- | --- | --- |
| 1 | `saltHex` | 7 | text |
| 2 | `version` | 7 | u32 = 3 |
| 3 | `nonceHex` | 8 | text |
| 4 | `keySource` | 9 | text = `active-key-hkdf-v1` |
| 5 | `ciphertextHex` | 13 | text |

与入参 `sealed` 结构一致，便于直接回填。

### 5.2 `local-secret.open`

map(1)，键序：`plaintext(9)` bytes。

> 现有实现的 hex 输出缓冲 `char ctHex[8192]` 在明文 > 4087 字节时
> `ToHex` 静默失败导致输出未初始化内存
> ——[0002](../../decisions/0002-差异清单.md) §1 B5。
> VLP 按 512 字节明文上限收敛，且要求编码器对缓冲不足**返回错误**。

## 6. 承诺覆盖对象

```
commitObject = {
  scope       text
  plaintext   bytes     （seal 时）
  或 sealed    map       （open 时）
}
```

**覆盖**：scope + 实际明文/密文字节。

## 7. grantScope

```
grantScope = { scope, sessionId, sessionEpoch }
```

同 scope 的多条请求可共用一条持续允许。
**跨 scope 不共用**；**不覆盖**导出与擦除。

## 8. 负向向量（必须确定失败）

| 情形 | 期望 |
| --- | --- |
| 换 scope 保留旧密文 | 解封失败 → `invalid-request` |
| 换 Key（换公钥） | 解封失败 |
| `version != 3` | `invalid-request` |
| `keySource != active-key-hkdf-v1` | `invalid-request` |
| `sealed` 对数 ≠ 5 | `invalid-request` |
| saltHex 解码 ≠ 16 字节 | `invalid-request` |
| nonceHex 解码 ≠ 12 字节 | `invalid-request` |
| 篡改 salt | AEAD 失败 → `invalid-request` |
| 篡改密文 | AEAD 失败 |
| 篡改 tag | AEAD 失败 |
| scope 含控制字符 | `invalid-request` |
| 空 scope | `invalid-request` |
| 明文超单帧限额 | `invalid-request` |

## 9. 与旧密文兼容验证

**必须**用**旧软件生成**的密文验证可解封——不是用本 Profile 自己的实现
生成再解开。V5 门禁要求该项有真实证据。

向量中的 `local-secret` 项使用固定公开测试私钥、固定 salt/nonce，
派生密钥与密文预期值由**独立参照实现**计算，不是 grep 源码常量
（现有脚本正是 grep 源码
——[0002](../../decisions/0002-差异清单.md) §6 G5）。