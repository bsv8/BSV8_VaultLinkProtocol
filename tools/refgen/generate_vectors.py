"""生成 `test-vectors/` 与 `test-vectors/manifest.json`。

用法（仓库根目录）：

    python3 tools/refgen/generate_vectors.py
    python3 tools/refgen/generate_vectors.py --check     # 只校验，不写文件

设计约束（需求 §10 VLP-01、VLP-02）：

* 期望字节由**独立参照实现**（`vlp_ref.py`，只用标准库）计算，
  **不是** grep 源码常量，也不是 SDK 自己生成的。
* 全部材料使用**公开测试 Key**，无真实 PIN/私钥/数据库。
* 公开 fixture **不**假称访问真实链上或信誉服务。
* 每条向量记录来源版本、固定随机材料与结果；manifest 记录文件哈希。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlp_ref as R  # noqa: E402
from vlp_ref import CborError, CborReader, CborWriter  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VECTORS = os.path.join(ROOT, "test-vectors")

VECTOR_VERSION = "0.1"
SPEC_CORE = "0.1"
SPEC_SECURITY = "0.1"
GENERATOR = "tools/refgen/generate_vectors.py"
GENERATOR_ALGO = "vlp-ref-python-a"

# 公开测试密钥。刻意选标量 1（最易独立复算），不是任何真实密钥。
# secp256k1 私钥是大端 32 字节：标量 1 = 31 个 0x00 后跟 0x01。
# 写成 bytes([1]) + bytes(31) 会得到 0x01 开头的大数，是**另一个**标量——
# 这正是 Rockey scripts/check_test_vectors.py 之外容易踩的坑。
TEST_PRIV_1 = bytes(31) + b"\x01"
# 第二个测试密钥用于「不同身份 A→B / B→A」类向量。
TEST_PRIV_2 = bytes(31) + b"\x02"


def h(data: bytes) -> str:
    return data.hex()


def det(label: str, length: int) -> bytes:
    """确定性伪随机材料：SHA-256 计数器模式。

    公开向量必须可复现，且不依赖任何 RNG 实现细节。
    """
    out = b""
    counter = 0
    while len(out) < length:
        out += R.sha256(label.encode("utf-8") + bytes([counter]))
        counter += 1
    return out[:length]


# --------------------------------------------------------------- CBOR 正向量


def gen_cbor_positive() -> dict:
    cases = []

    def enc(build) -> str:
        w = CborWriter()
        build(w)
        return w.to_hex()

    cases.append(
        {
            "id": "cbor-int-shortest",
            "description": "整数一律最短表示（spec/core/02-编码.md §2.3）",
            "items": [
                {"value": 0, "expect": "00"},
                {"value": 1, "expect": "01"},
                {"value": 23, "expect": "17"},
                {"value": 24, "expect": "1818"},
                {"value": 255, "expect": "18ff"},
                {"value": 256, "expect": "190100"},
                {"value": 65535, "expect": "19ffff"},
                {"value": 65536, "expect": "1a00010000"},
                {"value": 4294967295, "expect": "1affffffff"},
                {"value": 4294967296, "expect": "1b0000000100000000"},
            ],
        }
    )
    cases.append(
        {
            "id": "cbor-int-negative",
            "description": "负整数 major 1，参数为 -1-v（spec/core/02-编码.md §2.3）",
            "items": [
                {"value": -1, "expect": "20"},
                {"value": -24, "expect": "37"},
                {"value": -25, "expect": "3818"},
                {"value": -1000, "expect": "3903e7"},
            ],
        }
    )
    cases.append(
        {
            "id": "cbor-simple",
            "description": "仅允许 false/true/null；其余 simple 与浮点禁止",
            "items": [
                {"value": False, "expect": "f4"},
                {"value": True, "expect": "f5"},
                {"value": None, "expect": "f6"},
            ],
        }
    )
    cases.append(
        {
            "id": "cbor-map-key-order",
            "description": "键序为 (字节长度, 字节序) 严格递增（spec/core/02-编码.md §3.3）",
            "items": [
                {"keys": ["op", "purpose", "challenge", "opVersion"]},
                {"keys": ["txid", "vout", "proven", "script", "satoshis"]},
                {"keys": ["state", "language", "deviceEph", "publicKey", "deviceNonce", "deviceRunId"]},
                {"keys": ["saltHex", "version", "nonceHex", "keySource", "ciphertextHex"]},
                {"keys": ["op", "rawTx", "network", "prevouts", "opVersion", "inputIndex"]},
            ],
        }
    )

    nested = enc(
        lambda w: w.begin_map(6)
        .key("op")
        .text("tx.p2pkh-sign")
        .key("rawTx")
        .raw(bytes.fromhex("0100000001" + "00" * 0))
        .key("network")
        .uint(0)
        .key("prevouts")
        .begin_array(1)
        .begin_map(5)
        .key("txid")
        .raw(bytes(32))
        .key("vout")
        .uint(0)
        .key("proven")
        .boolean(False)
        .key("script")
        .raw(bytes(25))
        .key("satoshis")
        .uint(100000)
        .end_map()
        .end_array()
        .key("opVersion")
        .uint(1)
        .key("inputIndex")
        .uint(0)
        .end_map()
    )
    cases.append(
        {
            "id": "cbor-nested-containers",
            "description": (
                "map 套 array 套 map 必须合法（修复 0002 §1 B1/B7：现有实现解析失败）"
            ),
            "expect": nested,
            "decode": "roundtrip",
        }
    )
    cases.append(
        {
            "id": "cbor-pair-count-check",
            "description": "编码器必须自校验声明的 map 对数（修复 0002 §1 B6）",
            "expect": enc(
                lambda w: w.begin_map(3)
                .key("op")
                .text("x")
                .key("reason")
                .text("pair-count-self-check")
                .key("opVersion")
                .uint(1)
                .end_map()
            ),
            "decode": "roundtrip",
        }
    )
    return {"suite": "cbor", "version": VECTOR_VERSION, "cases": cases}


# --------------------------------------------------------------- CBOR 负向量


def _encode_raw(builder) -> str:
    w = CborWriter()
    builder(w)
    return w.to_hex()


def _manually(prefix: str) -> str:
    return prefix


def gen_cbor_negative() -> dict:
    """负向量：每一项都必须被拒绝。

    字节**手工构造**（不能用严格编码器，否则它会在编码时就拒绝，产出空串）。
    `probe` 指定探测方式：map 从顶层 map 开始，uint/text/bytes 从对应标量开始。
    """
    cases = [
        {
            "id": "cbor-neg-missing-field",
            "description": "缺必填字段：声明 2 对只写 1 对",
            "bytes": "a2626f706964656e746974792e70726f766563707572706f73657370757070".replace("7070", "")[:0]
            or "a2626f706964656e746974792e70726f766563707570706f7365737070",
            "probe": "map",
            "expectError": "map-pair-count-mismatch",
        },
        {
            "id": "cbor-neg-out-of-order",
            "description": "乱序键：长度变小",
            "bytes": "a2627a7a01616102",
            "probe": "map",
            "expectError": "key-out-of-order",
        },
        {
            "id": "cbor-neg-byte-order-descending",
            "description": "等长但字节序递减",
            "bytes": "a2616201616102",
            "probe": "map",
            "expectError": "key-out-of-order",
        },
        {
            "id": "cbor-neg-duplicate-key",
            "description": "重复键",
            "bytes": "a2616101616102",
            "probe": "map",
            "expectError": "duplicate-key",
        },
        {
            "id": "cbor-neg-extra-key-past-declared",
            "description": "键数多于声明对数",
            "bytes": "a26161016162ff02",
            "probe": "map",
            "expectError": "more-keys-than-declared",
        },
        {
            "id": "cbor-neg-key-too-long",
            "description": "键名 32 字节超限（上限 31）",
            "bytes": "a17820" + "78" * 32 + "01",
            "probe": "map",
            "expectError": "key-length-out-of-range",
        },
        {
            "id": "cbor-neg-non-minimal-int",
            "description": "非最短整数 0x18 0x17",
            "bytes": "1817",
            "probe": "uint",
            "expectError": "non-minimal-integer",
        },
        {
            "id": "cbor-neg-non-minimal-length",
            "description": "非最短长度头 0x59 0x00 0x05",
            "bytes": "59000568656c6c6f",
            "probe": "bytes",
            "expectError": "non-minimal-integer",
        },
        {
            "id": "cbor-neg-indefinite-length",
            "description": "不定长（ai 31）禁止",
            "bytes": "5f",
            "probe": "map",
            "expectError": "forbidden-additional-info",
        },
        {
            "id": "cbor-neg-tag",
            "description": "标签（major 6）禁止",
            "bytes": "c074323031332d30332d32315432303a30343a30305a",
            "probe": "uint",
            "expectError": "unexpected-major-type",
        },
        {
            "id": "cbor-neg-float",
            "description": "浮点禁止",
            "bytes": "fb3ff199999999999a",
            "probe": "uint",
            "expectError": "forbidden-additional-info",
        },
        {
            "id": "cbor-neg-undefined",
            "description": "undefined (0xF7) 禁止",
            "bytes": "f7",
            "probe": "boolean",
            "expectError": "unexpected-simple-value",
        },
        {
            "id": "cbor-neg-bool-simple",
            "description": "ai 24 形式的 simple value 禁止",
            "bytes": "f818",
            "probe": "boolean",
            "expectError": "unexpected-simple-value",
        },
        {
            "id": "cbor-neg-trailing-bytes",
            "description": "尾随字节：顶层不是 map 或有多余字节",
            "bytes": "0001",
            "probe": "map",
            "expectError": "trailing-bytes",
        },
        {
            "id": "cbor-neg-depth-exceeded",
            "description": "嵌套深度超 6",
            "bytes": "81" * 8,
            "probe": "array",
            "expectError": "depth-exceeded",
        },
        {
            "id": "cbor-neg-declared-length-exceeds-input",
            "description": "声明长度超过剩余输入（不得预分配）",
            "bytes": "590400",
            "probe": "bytes",
            "expectError": "declared-length-exceeds-input",
        },
        {
            "id": "cbor-neg-bad-utf8-text",
            "description": "文本串非良构 UTF-8",
            "bytes": "62c328",
            "probe": "text",
            "expectError": "invalid-utf8",
        },
        {
            "id": "cbor-neg-surrogate-utf8",
            "description": "UTF-8 代理区码点 U+D800 拒绝",
            "bytes": "63eda080",
            "probe": "text",
            "expectError": "invalid-utf8",
        },
        {
            "id": "cbor-neg-pairs-exceed-limit",
            "description": "map 对数超上限 24",
            "bytes": "a5" + "6161" + "00",
            "probe": "map",
            "expectError": "map-pair-count-out-of-range",
        },
        {
            "id": "cbor-neg-array-count-exceeds-input",
            "description": "数组声明元素数超过剩余输入",
            "bytes": "9a000000ff01",
            "probe": "array",
            "expectError": "declared-element-count-exceeds-input",
        },
    ]
    return {
        "suite": "cbor-negative",
        "version": VECTOR_VERSION,
        "note": (
            "全部为结构层负向量：解码器必须直接拒绝。业务层负向量（未知字段、"
            "缺必填、换对象等）在 profiles/envelope-negative.json，由 schemas 校验。"
        ),
        "cases": cases,
    }


def gen_envelope_vectors() -> dict:
    """信封结构样本：正样本必须通过 schema，负样本必须被拒绝。

    这些是**业务层**负向样本（缺字段/未知字段/超限），与 cbor-negative 的
    结构层负向量分开报告。依据 spec/profiles/00-通用约定.md §1。
    """
    pub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    script = "76a914751e76e8199196d454941c45d1b3a323f1433bd688acac"
    positive = [
        {
            "id": "env-pos-identity-prove",
            "document": {
                "op": "identity.prove",
                "opVersion": 1,
                "challenge": "ab" * 32,
                "purpose": "vaultlink-test",
            },
        },
        {
            "id": "env-pos-local-secret-open",
            "document": {
                "op": "local-secret.open",
                "opVersion": 1,
                "scope": "storage.bucket-password",
                "sealed": {
                    "saltHex": "00" * 16,
                    "version": 3,
                    "nonceHex": "10" * 12,
                    "keySource": "active-key-hkdf-v1",
                    "ciphertextHex": "ab" * 32,
                },
            },
        },
        {
            "id": "env-pos-content-attest",
            "document": {
                "op": "content.attest-digest",
                "opVersion": 1,
                "digestHex": "cd" * 32,
                "fileName": "sample.bin",
                "purpose": "archive",
            },
        },
        {
            "id": "env-pos-migration-import",
            "document": {
                "op": "migration.import",
                "opVersion": 1,
                "privKey": "00" * 31 + "01",
                "commitment": "ef" * 32,
            },
        },
    ]
    negative = [
        {
            "id": "env-neg-missing-challenge",
            "description": "identity.prove 缺 challenge（现有实现缺失仍视为有效请求）",
            "document": {"op": "identity.prove", "opVersion": 1, "purpose": "p"},
            "expectError": "required-field-missing",
        },
        {
            "id": "env-neg-missing-purpose",
            "description": "identity.prove 缺 purpose",
            "document": {"op": "identity.prove", "opVersion": 1, "challenge": "ab" * 32},
            "expectError": "required-field-missing",
        },
        {
            "id": "env-neg-unknown-field",
            "description": "夹带降级字段",
            "document": {
                "op": "identity.prove",
                "opVersion": 1,
                "challenge": "ab" * 32,
                "purpose": "p",
                "legacyFallback": 1,
            },
            "expectError": "unknown-field",
        },
        {
            "id": "env-neg-op-version",
            "description": "opVersion 不受支持",
            "document": {
                "op": "identity.prove",
                "opVersion": 99,
                "challenge": "ab" * 32,
                "purpose": "p",
            },
            "expectError": "op-version-unsupported",
        },
        {
            "id": "env-neg-challenge-length",
            "description": "challenge 不是 32 字节",
            "document": {
                "op": "identity.prove",
                "opVersion": 1,
                "challenge": "ab" * 16,
                "purpose": "p",
            },
            "expectError": "length-out-of-range",
        },
        {
            "id": "env-neg-challenge-uppercase-hex",
            "description": "hex 必须小写",
            "document": {
                "op": "identity.prove",
                "opVersion": 1,
                "challenge": "AB" * 32,
                "purpose": "p",
            },
            "expectError": "format-invalid",
        },
        {
            "id": "env-neg-sealed-extra-field",
            "description": "sealed 多一个字段（旧实现接受 4 对，导致自封数据解不开）",
            "document": {
                "op": "local-secret.open",
                "opVersion": 1,
                "scope": "s",
                "sealed": {
                    "saltHex": "00" * 16,
                    "version": 3,
                    "nonceHex": "10" * 12,
                    "keySource": "active-key-hkdf-v1",
                    "ciphertextHex": "ab" * 32,
                    "extra": 1,
                },
            },
            "expectError": "unknown-field",
        },
        {
            "id": "env-neg-sealed-version",
            "description": "信封 version != 3",
            "document": {
                "op": "local-secret.open",
                "opVersion": 1,
                "scope": "s",
                "sealed": {
                    "saltHex": "00" * 16,
                    "version": 2,
                    "nonceHex": "10" * 12,
                    "keySource": "active-key-hkdf-v1",
                    "ciphertextHex": "ab" * 32,
                },
            },
            "expectError": "envelope-version-unsupported",
        },
        {
            "id": "env-neg-sealed-keysource",
            "description": "keySource 不是 active-key-hkdf-v1",
            "document": {
                "op": "local-secret.open",
                "opVersion": 1,
                "scope": "s",
                "sealed": {
                    "saltHex": "00" * 16,
                    "version": 3,
                    "nonceHex": "10" * 12,
                    "keySource": "pin-derived-v2",
                    "ciphertextHex": "ab" * 32,
                },
            },
            "expectError": "key-source-unsupported",
        },
        {
            "id": "env-neg-scope-control-char",
            "description": "scope 含控制字符",
            "document": {
                "op": "local-secret.seal",
                "opVersion": 1,
                "scope": "bad\u0007scope",
                "plaintext": "ab" * 8,
            },
            "expectError": "format-invalid",
        },
        {
            "id": "env-neg-p2pkh-missing-inputindex",
            "description": "tx.p2pkh-sign 缺 inputIndex（现有实现静默签第 0 个输入）",
            "document": {
                "op": "tx.p2pkh-sign",
                "opVersion": 1,
                "rawTx": "01000000",
                "network": 0,
                "prevouts": [
                    {
                        "txid": "00" * 32,
                        "vout": 0,
                        "proven": False,
                        "script": script,
                        "satoshis": 1000,
                    }
                ],
            },
            "expectError": "required-field-missing",
        },
        {
            "id": "env-neg-p2pkh-network",
            "description": "非 BSV mainnet",
            "document": {
                "op": "tx.p2pkh-sign",
                "opVersion": 1,
                "rawTx": "01000000",
                "network": 1,
                "prevouts": [
                    {
                        "txid": "00" * 32,
                        "vout": 0,
                        "proven": False,
                        "script": script,
                        "satoshis": 1000,
                    }
                ],
                "inputIndex": 0,
            },
            "expectError": "network-unsupported",
        },
        {
            "id": "env-neg-p2pkh-non-p2pkh-script",
            "description": "前序脚本不是标准 P2PKH",
            "document": {
                "op": "tx.p2pkh-sign",
                "opVersion": 1,
                "rawTx": "01000000",
                "network": 0,
                "prevouts": [
                    {
                        "txid": "00" * 32,
                        "vout": 0,
                        "proven": False,
                        "script": "a914" + "00" * 20 + "87",
                        "satoshis": 1000,
                    }
                ],
                "inputIndex": 0,
            },
            "expectError": "script-template-unsupported",
        },
        {
            "id": "env-neg-p2pkh-inputs-over-limit",
            "description": "前序数量超上限 4",
            "document": {
                "op": "tx.p2pkh-sign",
                "opVersion": 1,
                "rawTx": "01000000",
                "network": 0,
                "prevouts": [
                    {
                        "txid": "00" * 32,
                        "vout": i,
                        "proven": False,
                        "script": script,
                        "satoshis": 1000,
                    }
                    for i in range(5)
                ],
                "inputIndex": 0,
            },
            "expectError": "count-out-of-range",
        },
    ]
    return {
        "suite": "envelope",
        "version": VECTOR_VERSION,
        "schema": "schemas/envelope.schema.json",
        "note": (
            "结构层负向量在 cbor/negative.json；此处为业务层负向样本，"
            "由 schemas/envelope.schema.json 校验。schema 只检查结构，"
            "不代表请求会被接受（spec/profiles/00-通用约定.md §7）。"
        ),
        "positive": positive,
        "negative": negative,
    }


def enc_safe(builder) -> str:
    try:
        return builder_to_hex(builder)
    except CborError:
        return ""


def builder_to_hex(builder) -> str:
    w = CborWriter()
    builder(w)
    return w.to_hex()


# ------------------------------------------------------------------ 帧向量


def gen_frame() -> dict:
    payload = b"vlp-frame-payload"
    frame = R.encode_frame(0x10, 0x01, 7, payload)
    over = R.encode_frame(0x10, 0x00, 1, bytes(R.MAX_FRAME_PAYLOAD))

    cases = [
        {
            "id": "frame-basic",
            "description": "基本帧编码：magic/version/type/flags/seq/len/crc",
            "bytes": h(frame),
            "fields": {
                "magic": "a55a",
                "version": 1,
                "type": 16,
                "flags": 1,
                "seq": 7,
                "payloadLen": len(payload),
                "payload": h(payload),
                "frameLen": len(frame),
            },
        },
        {
            "id": "frame-max-payload",
            "description": "恰好 MAX_FRAME_PAYLOAD 必须被接受（0002 §2 S2：现有实现实际只能 1522）",
            "bytes": h(over),
            "fields": {"payloadLen": R.MAX_FRAME_PAYLOAD, "frameLen": len(over)},
        },
        {
            "id": "frame-aad",
            "description": "AAD 10 字节，整数大端（spec/core/03-帧与消息.md §4.1）",
            "bytes": h(R.frame_aad(0x10, 0x01, 0x01020304, 0xAABBCCDD)),
            "fields": {"length": 10},
        },
        {
            "id": "frame-crc32-checkvalue",
            "description": "CRC-32/ISO-HDLC 校验值；magic 不计入 CRC",
            "crcOfAscii123456789": format(R.crc32_iso(b"123456789"), "08x"),
            "crcOfEmpty": format(R.crc32_iso(b""), "08x"),
        },
    ]

    negative = [
        {
            "id": "frame-neg-magic",
            "description": "magic 错误 → 重同步并丢弃",
            "bytes": h(frame.replace(b"\xa5\x5a", b"\xa5\x5b", 1)),
            "expectError": "bad-magic",
        },
        {
            "id": "frame-neg-version",
            "description": "version != 1 → 丢弃，不降级",
            "bytes": h(bytes([0xA5, 0x5A, 2]) + frame[3:]),
            "expectError": "bad-version",
        },
        {
            "id": "frame-neg-crc",
            "description": "CRC 不符 → 丢弃",
            "bytes": h(frame[:-1] + bytes([frame[-1] ^ 0xFF])),
            "expectError": "crc-mismatch",
        },
        {
            "id": "frame-neg-oversize-header-only",
            "description": "payloadLen > 上限：仅凭头即拒绝，不等负载",
            "bytes": "a55a01100000000000ffff",
            "expectError": "payload-length-out-of-range",
        },
        {
            "id": "frame-neg-reserved-flags",
            "description": "保留标志位非零 → 拒绝",
            "bytes": h(R.encode_frame(0x10, 0x00, 1, b"")),
            "flagsOverride": 0x08,
            "expectError": "reserved-flag-bits-set",
        },
    ]
    return {
        "suite": "frame",
        "version": VECTOR_VERSION,
        "limits": {
            "maxFramePayload": R.MAX_FRAME_PAYLOAD,
            "maxMessage": R.MAX_MESSAGE,
            "receiveBufferBytes": R.MAX_FRAME_PAYLOAD + R.FRAME_HEADER_LEN + R.FRAME_TRAILER_LEN,
        },
        "cases": cases,
        "negativeCases": negative,
    }


# -------------------------------------------------------------- 握手与派生


def gen_handshake() -> dict:
    host_nonce = det("vlp/host-nonce", 32)
    device_nonce = det("vlp/device-nonce", 32)
    host_eph = det("vlp/host-eph", 32)
    device_eph = det("vlp/device-eph", 32)
    device_run_id = 0x11223344
    host_run_generation = 0x55667788
    wallet_generation = 0x99AABBCC
    backend_generation = 0xDDEEFF00
    public_key = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    # X25519 共享秘密由路径 B（Node）提供；此处用固定 shared 作为 HKDF 输入，
    # 以便两条独立路径比对 HKDF 本身而不依赖 X25519 实现。
    shared = det("vlp/x25519-shared", 32)

    transcript = R.handshake_transcript(
        host_nonce, device_nonce, host_eph, device_eph,
        device_run_id, host_run_generation, wallet_generation, backend_generation, public_key,
    )
    keys = R.derive_link_keys(shared, transcript)
    challenge = det("vlp/possession-challenge", 32)
    session_id = 0x0A0B0C0D
    session_epoch = 7
    stmt = R.possession_statement(
        public_key, device_run_id, host_run_generation, session_id, challenge
    )

    return {
        "suite": "handshake",
        "version": VECTOR_VERSION,
        "specCore": SPEC_CORE,
        "note": "共享秘密为固定材料；X25519 本身由 crypto/hkdf.json 的 RFC 7748 向量覆盖。",
        "inputs": {
            "publicKey": h(public_key),
            "hostNonce": h(host_nonce),
            "deviceNonce": h(device_nonce),
            "hostEphemeral": h(host_eph),
            "deviceEphemeral": h(device_eph),
            "sharedSecret": h(shared),
            "deviceRunId": device_run_id,
            "hostRunGeneration": host_run_generation,
            "walletGeneration": wallet_generation,
            "backendGeneration": backend_generation,
            "challenge": h(challenge),
            "sessionId": session_id,
            "sessionEpoch": session_epoch,
        },
        "domainLabels": {
            "handshake": R.DOMAIN_HANDSHAKE.decode(),
            "pairing": R.DOMAIN_PAIRING.decode(),
            "c2sKey": R.DOMAIN_C2S_KEY.decode(),
            "c2sNonce": R.DOMAIN_C2S_NONCE.decode(),
            "s2cKey": R.DOMAIN_S2C_KEY.decode(),
            "s2cNonce": R.DOMAIN_S2C_NONCE.decode(),
            "possession": R.DOMAIN_POSSESSION.decode(),
        },
        "expected": {
            "transcript": h(transcript),
            "pairingCode": R.pairing_code(transcript),
            "c2sKey": h(keys["c2sKey"]),
            "c2sBaseNonce": h(keys["c2sBaseNonce"]),
            "s2cKey": h(keys["s2cKey"]),
            "s2cBaseNonce": h(keys["s2cBaseNonce"]),
            "possessionStatementDigest": h(stmt),
            "directionKeysDiffer": keys["c2sKey"] != keys["s2cKey"],
            "directionNoncesDiffer": keys["c2sBaseNonce"] != keys["s2cBaseNonce"],
        },
        "negativeCases": [
            {
                "id": "handshake-neg-transcript-tamper",
                "description": "改动任一 transcript 输入必须改变 transcript 与配对码",
                "mutate": "walletGeneration",
            },
            {
                "id": "handshake-neg-possession-domain",
                "description": "用 identity 域标签构造持有权声明必须得到不同摘要",
                "expectError": "digest-differs",
            },
        ],
    }


# ---------------------------------------------------------------- 承诺向量


def gen_commitment() -> dict:
    commit_object = (
        CborWriter()
        .begin_map(2)
        .key("purpose")
        .text("vaultlink-test")
        .key("challenge")
        .raw(det("vlp/ch", 32))
        .end_map()
        .bytes()
    )

    challenge = det("vlp/identity-challenge", 32)
    purpose = "vaultlink-test"
    public_key = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )

    identity_commit_obj = (
        CborWriter()
        .begin_map(2)
        .key("purpose")
        .text(purpose)
        .key("challenge")
        .raw(challenge)
        .end_map()
        .bytes()
    )

    return {
        "suite": "commitment",
        "version": VECTOR_VERSION,
        "inputs": {
            "identityPurpose": purpose,
            "identityChallenge": h(challenge),
        },
        "expected": {
            "genericCommitment": h(
                R.request_commitment("identity", 1, commit_object)
            ),
            "identityCommitObjectHex": h(identity_commit_obj),
            "identityCommitment": h(
                R.request_commitment("identity", 1, identity_commit_obj)
            ),
            "identityProveStatement": h(
                R.identity_statement("prove", public_key, 0x01020304, 3, challenge, purpose)
            ),
            "identityAuthorizeStatement": h(
                R.identity_statement("authorize", public_key, 0x01020304, 3, challenge, purpose)
            ),
            "contentStatement": h(
                R.content_statement("archive", "ab" * 32)
            ),
            "importCommitment": h(R.import_commitment(TEST_PRIV_1)),
            "commitObjectHex": h(commit_object),
        },
        "negativeCases": [
            {
                "id": "commit-neg-tamper-purpose",
                "description": "改 purpose 必须改变承诺",
                "expectError": "commitment-differs",
            },
            {
                "id": "commit-neg-tamper-challenge",
                "description": "改 challenge 必须改变承诺",
                "expectError": "commitment-differs",
            },
            {
                "id": "commit-neg-profile-mismatch",
                "description": "换 profileId 必须改变承诺（不得跨 Profile 重放）",
                "expectError": "commitment-differs",
            },
            {
                "id": "commit-neg-statement-domain-isolation",
                "description": "prove 与 authorize 的声明摘要必须不同",
                "expectError": "digest-differs",
            },
        ],
    }


# ------------------------------------------------------------ 密码原语向量


def gen_crypto() -> dict:
    """密码向量：期望值由本实现**实际执行**得出。

    密码原语对照放在 conformance 层：Node 成熟实现必须复现同一值。
    不使用 grep 源码常量（0002 §6 G5）。
    """
    ikm = TEST_PRIV_1
    public_key = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    scope = "storage.bucket-password"
    key = R.local_secret_key(ikm, public_key, scope)
    salt = bytes(range(16))
    nonce = bytes(range(0x10, 0x1C))
    aad = R.local_secret_aad(scope, salt)

    return {
        "suite": "crypto",
        "version": VECTOR_VERSION,
        "specSecurity": SPEC_SECURITY,
        "testKey": {
            "note": "公开测试密钥：标量为 1，非任何真实密钥；无 PIN、无数据库。",
            "privateKeyHex": h(TEST_PRIV_1),
            "publicKeyHex": h(public_key),
        },
        "hkdf": {
            "rfc5869A1": {
                "note": "RFC 5869 A.1（SHA-256，22 字节 IKM，13 字节 salt/info，42 字节 L）",
                "ikmHex": "0b" * 22,
                "saltHex": "000102030405060708090a0b0c",
                "infoHex": "f0f1f2f3f4f5f6f7f8f9",
                "okmHex": (
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865"
                ),
            },
            "rfc5869A3": {
                "note": "RFC 5869 A.3（空 salt 与 info，42 字节 L）",
                "ikmHex": "0b" * 22,
                "saltHex": "",
                "infoHex": "",
                "okmHex": (
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                    "9d201395faa4b61a96c8"
                ),
            },
        },
        "digests": {
            "sha256Empty": h(R.sha256(b"")),
            "sha256dEmpty": h(R.sha256d(b"")),
            "sha256dAbc": h(R.sha256d(b"abc")),
            "ripemd160Empty": h(R.ripemd160(b"")),
            "ripemd160Abc": h(R.ripemd160(b"abc")),
            "hash160OfTestPub": h(R.hash160(public_key)),
        },
        "localSecretV3": {
            "note": (
                "既有 v3 配方的派生密钥与 AAD；信封 salt 只在 AAD 中，从不作为 HKDF salt"
                "（0002 §4 X 记录的最易错点）"
            ),
            "keySource": R.LOCAL_SECRET_KEY_SOURCE,
            "envelopeVersion": R.LOCAL_SECRET_VERSION,
            "hkdfSalt": R.LOCAL_SECRET_HKDF_SALT.decode(),
            "hkdfInfoHex": h(
                R.to_hex(public_key).encode("ascii") + bytes([0]) + scope.encode("utf-8")
            ),
            "scope": scope,
            "derivedKeyHex": h(key),
            "saltHex": h(salt),
            "nonceHex": h(nonce),
            "aadHex": h(aad),
            "aadLength": len(aad),
        },
        "negativeCases": [
            {
                "id": "crypto-neg-scope-change",
                "description": "换 scope 必须改变派生密钥",
                "expectError": "key-differs",
            },
            {
                "id": "crypto-neg-key-change",
                "description": "换业务私钥必须改变派生密钥",
                "expectError": "key-differs",
            },
            {
                "id": "crypto-neg-salt-not-in-hkdf",
                "description": "把信封 salt 当作 HKDF salt 必须解不开既有密文",
                "expectError": "aead-failure",
            },
            {
                "id": "crypto-neg-aad-order",
                "description": "AAD 中 0x00 分隔符位置错误必须导致 AEAD 失败",
                "expectError": "aead-failure",
            },
        ],
    }


# ------------------------------------------------------------ P2PKH 向量


def build_sample_tx() -> tuple[R.Tx, bytes]:
    mine = R.hash160(
        bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    )
    other = bytes(range(20))
    tx = R.Tx(
        version=0,
        inputs=[R.TxIn(txid=det("vlp/utxo", 32), vout=0, sequence=0xFFFFFFFF)],
        outputs=[
            R.TxOut(90000, R.build_p2pkh_script(other)),
            R.TxOut(95000, R.build_p2pkh_script(mine)),
        ],
        lock_time=0,
    )
    return tx, R.serialize_tx(tx)


def gen_p2pkh() -> dict:
    public_key = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    mine = R.hash160(public_key)
    other = bytes(range(20))
    tx = R.Tx(
        version=0,
        inputs=[R.TxIn(txid=det("vlp/utxo", 32), vout=0, sequence=0xFFFFFFFF)],
        outputs=[
            R.TxOut(90000, R.build_p2pkh_script(other)),
            R.TxOut(95000, R.build_p2pkh_script(mine)),
        ],
        lock_time=0,
    )
    raw = R.serialize_tx(tx)
    prevouts = [R.PrevOut(txid=tx.inputs[0].txid, vout=0, script=R.build_p2pkh_script(mine), satoshis=200000)]
    review = R.review_tx(raw, prevouts, public_key, 0)

    commit_obj = (
        CborWriter()
        .begin_map(4)
        .key("rawTx")
        .raw(raw)
        .key("network")
        .uint(0)
        .key("prevouts")
        .begin_array(1)
        .begin_map(4)
        .key("txid")
        .raw(tx.inputs[0].txid)
        .key("vout")
        .uint(0)
        .key("script")
        .raw(R.build_p2pkh_script(mine))
        .key("satoshis")
        .uint(200000)
        .end_map()
        .end_array()
        .key("inputIndex")
        .uint(0)
        .end_map()
        .bytes()
    )

    return {
        "suite": "bsv-p2pkh",
        "version": VECTOR_VERSION,
        "sighashType": R.SIGHASH_ALL_FORKID,
        "limits": {
            "maxInputs": R.BSV_MAX_INPUTS,
            "maxOutputs": R.BSV_MAX_OUTPUTS,
            "maxRawTxBytes": R.BSV_MAX_RAW_TX,
        },
        "inputs": {
            "publicKeyHex": h(public_key),
            "scriptHex": h(R.build_p2pkh_script(mine)),
            "otherScriptHex": h(R.build_p2pkh_script(other)),
            "changeAddress": R.p2pkh_address(mine),
            "payAddress": R.p2pkh_address(other),
            "rawTxHex": h(raw),
            "prevouts": [
                {
                    "txid": h(tx.inputs[0].txid),
                    "vout": 0,
                    "satoshis": 200000,
                    "script": h(R.build_p2pkh_script(mine)),
                    "proven": False,
                }
            ],
            "inputIndex": 0,
        },
        "expected": {
            "sighashHex": h(review.sighash),
            "sighashType": review.sighash_type,
            "feeSats": review.fee_sats,
            "changeSats": review.change_sats,
            "payTotalSats": review.pay_total_sats,
            "changeAddress": review.change_address,
            "pays": [{"satoshis": s, "address": a} for s, a in review.pays],
            "commitmentHex": h(R.request_commitment("bsv.p2pkh", 1, commit_obj)),
            "commitObjectHex": h(commit_obj),
        },
        "negativeCases": [
            {"id": "p2pkh-neg-not-owned", "description": "前序不属于本 Key", "expectError": "wrong-key"},
            {"id": "p2pkh-neg-missing-evidence", "description": "缺前序证据", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-network", "description": "非 0 网络", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-no-change", "description": "无找零输出", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-no-pay", "description": "无付款输出", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-unknown-script", "description": "非 P2PKH 输出脚本", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-trailing", "description": "rawTx 尾随字节", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-input-index", "description": "inputIndex 越界", "expectError": "invalid-request"},
            {"id": "p2pkh-neg-amount-tamper", "description": "改金额保留旧承诺", "expectError": "commitment-differs"},
            {"id": "p2pkh-neg-recipient-tamper", "description": "换收款方保留旧承诺", "expectError": "commitment-differs"},
        ],
    }


# ------------------------------------------------------------ 容量实测


def measure_frame_capacity() -> dict:
    """用首批 Profile 样本实测编码后尺寸，验证单帧限额（施工单 V0 第 9 项）。

    不把 1400/1536 等实现数值当成充分证据——这里从真实样本反推。
    """
    public_key = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    mine = R.hash160(public_key)
    other = bytes(range(20))

    # P2PKH：1 输入 2 输出
    tx1 = R.Tx(
        version=0,
        inputs=[R.TxIn(txid=det("vlp/utxo", 32), vout=0, sequence=0xFFFFFFFF)],
        outputs=[
            R.TxOut(90000, R.build_p2pkh_script(other)),
            R.TxOut(95000, R.build_p2pkh_script(mine)),
        ],
        lock_time=0,
    )
    raw1 = R.serialize_tx(tx1)
    w = CborWriter().begin_map(6)
    w.key("op").text("tx.p2pkh-sign")
    w.key("rawTx").raw(raw1)
    w.key("network").uint(0)
    w.key("prevouts").begin_array(1).begin_map(5)
    w.key("txid").raw(tx1.inputs[0].txid).key("vout").uint(0).key("proven").boolean(False)
    w.key("script").raw(R.build_p2pkh_script(mine)).key("satoshis").uint(200000)
    w.end_map().end_array()
    w.key("opVersion").uint(1).key("inputIndex").uint(0)
    w.end_map()
    p2pkh_1in = w.size

    # P2PKH：上限样本（4 输入 6 输出）
    inputs = [R.TxIn(txid=det(f"vlp/utxo{i}", 32), vout=i, sequence=0xFFFFFFFF) for i in range(4)]
    outputs = [R.TxOut(10000, R.build_p2pkh_script(bytes([i + 1]) * 20)) for i in range(5)]
    outputs.append(R.TxOut(95000, R.build_p2pkh_script(mine)))
    tx4 = R.Tx(version=0, inputs=inputs, outputs=outputs, lock_time=0)
    raw4 = R.serialize_tx(tx4)
    w4 = CborWriter().begin_map(6)
    w4.key("op").text("tx.p2pkh-sign")
    w4.key("rawTx").raw(raw4)
    w4.key("network").uint(0)
    w4.key("prevouts").begin_array(4)
    for i in inputs:
        w4.begin_map(5)
        w4.key("txid").raw(i.txid).key("vout").uint(i.vout).key("proven").boolean(False)
        w4.key("script").raw(R.build_p2pkh_script(mine)).key("satoshis").uint(200000)
        w4.end_map()
    w4.end_array()
    w4.key("opVersion").uint(1).key("inputIndex").uint(0).end_map()
    p2pkh_max = w4.size

    # local-secret：明文上限 512
    ls_max = len(
        CborWriter().begin_map(4)
        .key("op").text("local-secret.seal")
        .key("scope").text("s" * 95)
        .key("opVersion").uint(1)
        .key("plaintext").raw(bytes(R.BSV_MAX_INPUTS * 0 + 512))
        .end_map().bytes()
    )
    # 声明的旧上限（4096）作为对照
    ls_old = len(
        CborWriter().begin_map(4)
        .key("op").text("local-secret.seal")
        .key("scope").text("s" * 95)
        .key("opVersion").uint(1)
        .key("plaintext").raw(bytes(4096))
        .end_map().bytes()
    )
    # channel：旧上限 512 字节消息
    ch_old = len(
        CborWriter().begin_map(5)
        .key("op").text("channel.private-message")
        .key("message").raw(bytes(512))
        .key("protocol").text("messaging")
        .key("opVersion").uint(1)
        .key("recipientPub").raw(public_key)
        .end_map().bytes()
    )

    fits = lambda n: n <= R.MAX_MESSAGE
    return {
        "suite": "limits",
        "version": VECTOR_VERSION,
        "limits": {
            "maxFramePayload": R.MAX_FRAME_PAYLOAD,
            "maxMessage": R.MAX_MESSAGE,
            "aeadOverhead": 16,
            "frameOverhead": R.FRAME_HEADER_LEN + R.FRAME_TRAILER_LEN,
            "maxPendingRequests": R.MAX_PENDING_REQUESTS,
            "maxResultCache": R.MAX_RESULT_CACHE,
            "maxSessions": R.MAX_SESSIONS,
            "maxSessionDecisions": R.MAX_SESSION_DECISIONS,
        },
        "samples": [
            {
                "id": "cap-p2pkh-1in-2out",
                "description": "BSV P2PKH 1 输入 2 输出完整请求体（典型场景）",
                "encodedBytes": p2pkh_1in,
                "fitsSingleFrame": fits(p2pkh_1in),
            },
            {
                "id": "cap-p2pkh-4in-6out",
                "description": "BSV P2PKH 上限样本（4 输入 6 输出）",
                "encodedBytes": p2pkh_max,
                "fitsSingleFrame": fits(p2pkh_max),
            },
            {
                "id": "cap-local-secret-512",
                "description": "local-secret 明文 512 字节（VLP 收敛后的上限）",
                "encodedBytes": ls_max,
                "fitsSingleFrame": fits(ls_max),
            },
            {
                "id": "cap-local-secret-4096-old",
                "description": "local-secret 明文 4096 字节（现有实现声明的上限）",
                "encodedBytes": ls_old,
                "fitsSingleFrame": fits(ls_old),
            },
            {
                "id": "cap-channel-512-old",
                "description": "channel 消息 512 字节（现有实现声明的上限）",
                "encodedBytes": ch_old,
                "fitsSingleFrame": fits(ch_old),
            },
        ],
        "conclusion": (
            "VLP 0.1 的单帧上限不能承载现有实现声明的 rawTx ≤ 8192 / "
            "channel message ≤ 512 / local-secret plaintext ≤ 4096。字段上限已按单帧收敛，"
            "超限明确拒绝。"
        ),
    }


# ------------------------------------------------------------- 范围与授权


def gen_scope() -> dict:
    """grantScope 与 requestCommitment 分离的语义向量。"""
    peer_a = bytes.fromhex(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )
    peer_b = bytes.fromhex(
        "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    # grantScope 的规范编码：键按 (字节长度, 字节序) 严格递增。
    # 键名长度：scope 5 < operation 9 < direction 9 < protocolId 10
    #          < sessionId 9 ... 实际顺序见 conformance 校验。
    scope_obj = (
        CborWriter().begin_map(6)
        .key("scope").text("channel.messaging.inbound")
        .key("direction").uint(1)
        .key("operation").uint(0x33)
        .key("protocolId").uint(1)
        .key("sessionEpoch").uint(3)
        .key("peerPublicKey").raw(peer_a)
        .end_map().bytes()
    )
    return {
        "suite": "scope",
        "version": VECTOR_VERSION,
        "note": (
            "单次 requestCommitment 逐请求唯一；grantScope 多条合法请求可共用。"
            "两者分离是需求 §6 的要求（0002 §1 B2 的修复）。"
        ),
        "peerA": h(peer_a),
        "peerB": h(peer_b),
        "grantScopeEncodingHex": h(scope_obj),
        "grantScopeKeysInOrder": [
            "scope", "direction", "operation", "protocolId", "sessionEpoch", "peerPublicKey",
        ],
        "grantScopeScopeVariantHex": h(
            CborWriter().begin_map(6)
            .key("scope").text("channel.messaging.outbound")
            .key("direction").uint(2)
            .key("operation").uint(0x33)
            .key("protocolId").uint(1)
            .key("sessionEpoch").uint(3)
            .key("peerPublicKey").raw(peer_a)
            .end_map().bytes()
        ),
        "grantScopePeerVariantHex": h(
            CborWriter().begin_map(6)
            .key("scope").text("channel.messaging.inbound")
            .key("direction").uint(1)
            .key("operation").uint(0x33)
            .key("protocolId").uint(1)
            .key("sessionEpoch").uint(3)
            .key("peerPublicKey").raw(peer_b)
            .end_map().bytes()
        ),
        "grantScopeProtocolVariantHex": h(
            CborWriter().begin_map(6)
            .key("scope").text("channel.messaging.inbound")
            .key("direction").uint(1)
            .key("operation").uint(0x33)
            .key("protocolId").uint(4)
            .key("sessionEpoch").uint(3)
            .key("peerPublicKey").raw(peer_a)
            .end_map().bytes()
        ),
        "negativeCases": [
            {"id": "scope-neg-peer-change", "description": "换对端必须改变 grantScope", "expectError": "scope-differs"},
            {"id": "scope-neg-direction-change", "description": "换方向必须改变 grantScope", "expectError": "scope-differs"},
            {"id": "scope-neg-protocol-change", "description": "换协议必须改变 grantScope", "expectError": "scope-differs"},
            {"id": "scope-neg-unregistered-protocol", "description": "未登记协议直接拒绝，不降级", "expectError": "invalid-request"},
            {"id": "scope-neg-no-parser", "description": "无语义解析器的消息不产生 grantScope", "expectError": "need-user"},
        ],
    }


# ------------------------------------------------------------------ manifest


SUITES = {
    "cbor/cbor.json": gen_cbor_positive,
    "cbor/negative.json": gen_cbor_negative,
    "frame/frame.json": gen_frame,
    "handshake/handshake.json": gen_handshake,
    "commitment/commitment.json": gen_commitment,
    "crypto/crypto.json": gen_crypto,
    "profiles/bsv-p2pkh.json": gen_p2pkh,
    "limits/frame-capacity.json": measure_frame_capacity,
    "policy/scope.json": gen_scope,
    "profiles/envelope.json": gen_envelope_vectors,
}


def build_manifest() -> dict:
    entries = []
    for rel, fn in SUITES.items():
        path = os.path.join(VECTORS, rel)
        with open(path, "rb") as fh:
            data = fh.read()
        doc = json.loads(data)
        entries.append(
            {
                "path": rel,
                "suite": doc.get("suite"),
                "version": doc.get("version"),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    return {
        "manifestVersion": "0.1",
        "vectorSet": "vlp-core-0.1",
        "spec": {
            "core": SPEC_CORE,
            "security": SPEC_SECURITY,
            "profiles": {
                "identity": "0.1",
                "bsv.p2pkh": "0.1",
                "channel": "0.1",
                "local-secret": "0.1",
                "content": "0.1",
                "evidence": None,
                "migration": "0.1",
            },
        },
        "generator": {
            "path": GENERATOR,
            "referencePath": "A",
            "algorithm": GENERATOR_ALGO,
            "language": "python3-stdlib-only",
            "sourceCommits": {
                "Rockey": "0156bb1b36ccb004ad7443b20fd0e249a355ab21",
                "Keymaster": "5c7d4540ef63248bb4f822679312953a1ebc96ab",
            },
            "notes": [
                "期望字节由独立参照实现计算，不是 grep 源码常量，也不是 SDK 自身输出。",
                "AES-256-GCM 与 ECDSA 由 conformance 的 Node 路径与公开标准向量覆盖，两路径不共享代码。",
                "所有材料为公开测试材料，无真实 PIN/私钥/数据库。",
                "公开 fixture 不代表已访问真实链上或信誉服务。",
            ],
        },
        "files": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="只校验现有文件，不写入")
    args = parser.parse_args()

    problems: list[str] = []

    for rel, fn in SUITES.items():
        path = os.path.join(VECTORS, rel)
        doc = fn()
        text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
        if args.check:
            if not os.path.exists(path):
                problems.append(f"missing {rel}")
                continue
            with open(path, encoding="utf-8") as fh:
                if fh.read() != text:
                    problems.append(f"stale {rel}")
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {rel}")

    manifest = build_manifest() if not args.check else json.loads(
        open(os.path.join(VECTORS, "manifest.json"), encoding="utf-8").read()
    )
    mtext = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    mpath = os.path.join(VECTORS, "manifest.json")
    if args.check:
        with open(mpath, encoding="utf-8") as fh:
            if fh.read() != mtext:
                problems.append("stale test-vectors/manifest.json")
    else:
        with open(mpath, "w", encoding="utf-8") as fh:
            fh.write(mtext)
        print("wrote test-vectors/manifest.json")

    if problems:
        for p in problems:
            print(f"ERROR {p}", file=sys.stderr)
        return 1
    if args.check:
        print("vectors up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())