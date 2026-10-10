# Channel 互通（wire 2）

延续既有 Channel 施工范围，以 bsv8-channel-protocol@0.6.0 实际 wire 为权威。旧 wire 1 的 rockey:channel 域与 X25519 不能用于这里。

操作 channel.public-message / channel.hash-request / channel.private-message / channel.seal / channel.open。Profile 为 bsv8-channel-public / bsv8-channel-hash / bsv8-channel-private / bsv8-channel-seal / bsv8-channel-open，版本 1；body 固定 `{message:bytes}`，完整承诺覆盖这些实际字节，不传主机摘要、ECDH 密钥或批准字段。

前三项 message 是该 SDK 签名逻辑对象的完整 RFC 8785 JCS UTF-8，含 scope、channel、from_public_key、message。public/hash scope=bsv8.public-message.v1，private scope=bsv8.private-message.v1。设备独立检查规范化、自己公钥、精确频道、32 字节 base64url message_id、合法安全整数时间和寿命。Hash 频道固定 bsv8.hash.request.v1；私密频道 bsv8.inbox.<收件人压缩公钥>。签名为 SHA256(JCS) 的 strict DER low-S，与现有 SDK 一致。

seal 的 message 为完整已签私密消息 JCS（包含 channel/from_public_key），设备核验自己签名，自己产生 salt32/nonce12，执行 secp256k1 ECDH_x、HKDF-SHA256、AES-256-GCM，返回原 SDK 的完整 JSON 信封。open 的 message 为完整原 SDK JSON 信封；设备匹配自己的收件箱、解密、核验发送人签名及时间/协议后，批准才返回完整已签明文。只支持实际 0.6.0 已登记的 bsv8.message.v1 / bsv8.ping.v1 / bsv8.webrtc.signal.v1；业务含义仍在 Keymaster。

设备子集：JCS 输入≤16384 字节、≤256 值与键节点、嵌套≤12，解析树累计规范文本≤32768 字节，先检查再分配。数值使用固定 Google double-conversion 3.3.1 的 ECMAScript 双向转换；UTF-16 键序、孤立 surrogate、重复键、非有限数、不规范数字/转义、尾随内容都拒绝，不能退回签摘要。

基础解释包括操作、频道、对端、子协议、message_id、时间及实际对象哈希。public/hash 持续决定限定操作+精确频道；私密出站签名/seal 共用 peer+protocol+outbound，入站 open 用 peer+protocol+inbound。决定仅当前 USB 连接有效，由设备取消允许或否决；付款、身份/意图和迁移不使用 Channel 决定。
