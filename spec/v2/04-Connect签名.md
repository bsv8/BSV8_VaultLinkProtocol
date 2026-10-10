# Connect 身份与意图签名（wire 2）

这是原施工单的 Connect 语义签名工序，匹配 Keymaster Connect v1 的实际信封，不使用旧 wire 1 identity.prove 声明代替 App 签名。

操作 `connect.identity-sign` / `connect.intent-sign`，Profile 分别为 `connect-identity-envelope` / `connect-intent-envelope`，版本 1。identity body 为 `{envelope:bytes}`，intent body 为 `{envelope:bytes,content:bytes}`。承诺覆盖整个 body；不接收主机提供的 digest、签名格式或批准决定。

identity 信封是确定性 CBOR 数组 `[1,requestId,aud,iat,exp,text,publicKey,claims]`；intent 是 `[1,requestId,aud,iat,exp,text,contentType,SHA256(content),publicKey]`。设备解码并规范重编码，逐字段核验：公钥为设备自己的压缩公钥；iat/exp 为非负安全整数且 exp>iat；requestId 1–128 UTF-8 字节、aud 1–512、text 0–2048、contentType 1–127；intent 完整内容与哈希一致。信封解码最多 256 个 CBOR 值节点，分配前检查；信封不超过 8192 字节，intent 内容不超过 16384 字节。claims 为最多 32 个 `[name,value]`，名称 1–128 字节、按 UTF-8 字节序严格递增；值保持现有确定性 CBOR 支持的整数/文本/布尔/null/bytes/array/map，不接受浮点、尾随数据或非最短编码。超出设备能力明确失败，不能改签摘要。

设备基础解释显示签名类型、aud、requestId、iat/exp、identity 的 claim 名称或 intent 的类型/内容长度、信封和内容哈希。业务文本/可信度解释仍由 Keymaster 完成。每次须实体批准，不提供持续身份/意图批准。取消、断线、锁定或世代变化使未完成签名失效。设备无可信 RTC，不声称独立证明时间有效；Keymaster 按 Connect 规则检查请求时间。

结果 `{publicKey:bytes33,signature:strict-low-S-DER}`，签名摘要为 `SHA256(envelope)`，与当前 Connect v1 单 SHA-256/compact-low-S 验签完全一致。SDK 验证 DER/公钥/摘要后转换为 compact 64 字节供 Connect 返回；不增加恢复 ID、不再次哈希。该操作不会花费金额，不进入支付额度账本，也不能替代费用池/交易签名。
