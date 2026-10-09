"""路径 A 自检：验证参照实现本身遵守 `VLP-CBOR-1`。

这些断言**不依赖** test-vectors（向量是本实现生成的，用它们自检是循环论证）。
目的是保证「生成期望值的那个实现」本身是对的。

规范：spec/core/02-编码.md、spec/core/03-帧与消息.md。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlp_ref as R  # noqa: E402
from vlp_ref import CborError, CborReader, CborWriter  # noqa: E402

FAILURES: list[str] = []


def ok(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  PASS {label}" + (f" — {detail}" if detail else ""))
    else:
        print(f"  FAIL {label}" + (f" — {detail}" if detail else ""))
        FAILURES.append(label)


def expect_error(label: str, fn) -> None:
    try:
        fn()
    except (CborError, ValueError) as exc:
        ok(label, True, str(exc)[:60])
    else:
        ok(label, False, "未被拒绝")


def main() -> int:
    print("摘要原语")
    ok("CRC-32/ISO-HDLC 校验值", R.crc32_iso(b"123456789") == 0xCBF43926)
    ok("CRC-32 空输入为 0", R.crc32_iso(b"") == 0)
    ok("SHA-256(abc)", R.sha256(b"abc").hex() ==
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    ok("SHA256d(abc)", R.sha256d(b"abc").hex() ==
       "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
    ok("RIPEMD-160(abc)", R.ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    ok("HMAC-SHA256 RFC 4231 case 2",
       R.hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() ==
       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    ok("HKDF RFC 5869 A.1",
       R.hkdf_sha256(bytes([0x0B]) * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42).hex() ==
       "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
       "34007208d5b887185865")
    ok("HKDF RFC 5869 A.3（空 salt/info）",
       R.hkdf_sha256(bytes([0x0B]) * 22, b"", b"", 42).hex() ==
       "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
       "9d201395faa4b61a96c8")

    print("\n整数最短表示")
    for value, want in [(0, "00"), (23, "17"), (24, "1818"), (255, "18ff"),
                        (256, "190100"), (65535, "19ffff"), (65536, "1a00010000"),
                        (4294967295, "1affffffff"), (4294967296, "1b0000000100000000")]:
        got = CborWriter().uint(value).to_hex()
        ok(f"uint({value})", got == want, f"{got}" + ("" if got == want else f" want {want}"))
    for value, want in [(-1, "20"), (-24, "37"), (-25, "3818"), (-1000, "3903e7")]:
        got = CborWriter().int(value).to_hex()
        ok(f"int({value})", got == want, f"{got}" + ("" if got == want else f" want {want}"))

    print("\n键序规则（长度优先再字节序）")
    CborWriter().begin_map(4).key("op").text("x").key("purpose").text("p") \
        .key("challenge").raw(bytes(32)).key("opVersion").uint(1).end_map()
    ok("递增键序被接受", True)
    expect_error("乱序（长度变小）",
                 lambda: CborWriter().begin_map(2).key("zz").uint(1).key("a").uint(2).end_map())
    expect_error("等长字节序递减",
                 lambda: CborWriter().begin_map(2).key("b").uint(1).key("a").uint(2).end_map())
    expect_error("重复键",
                 lambda: CborWriter().begin_map(2).key("a").uint(1).key("a").uint(2).end_map())
    expect_error("键名 32 字节超限",
                 lambda: CborWriter().begin_map(1).key("x" * 32).uint(1).end_map())

    print("\n编码器自校验（B6 修复）")
    expect_error("声明 3 对只写 1 对",
                 lambda: CborWriter().begin_map(3).key("op").text("x").end_map())
    expect_error("键数多于声明",
                 lambda: CborWriter().begin_map(1).key("a").uint(1).key("b").uint(2).end_map())
    expect_error("未闭合容器",
                 lambda: CborWriter().begin_map(1).key("a").uint(1).bytes())
    expect_error("数组元素数不符",
                 lambda: CborWriter().begin_array(2).uint(1).end_array())

    print("\n嵌套容器（B1/B7 修复：容器状态按层级栈）")
    w = CborWriter()
    w.begin_map(6)
    w.key("op").text("tx.p2pkh-sign")
    w.key("rawTx").raw(bytes.fromhex("0100000001"))
    w.key("network").uint(0)
    w.key("prevouts").begin_array(1).begin_map(5)
    w.key("txid").raw(bytes(32))
    w.key("vout").uint(0)
    w.key("proven").boolean(False)
    w.key("script").raw(bytes(25))
    w.key("satoshis").uint(100000)
    w.end_map().end_array()
    w.key("opVersion").uint(1)
    w.key("inputIndex").uint(0)
    w.end_map()
    ok("map 套 array 套 map 可编码", w.size > 0, f"{w.size} 字节")

    r = CborReader(w.bytes())
    n = r.begin_map()
    seen = []
    for _ in range(n):
        k = r.map_key()
        seen.append(k)
        if k == "prevouts":
            c = r.begin_array()
            for _ in range(c):
                p = r.begin_map()
                for _ in range(p):
                    kk = r.map_key()
                    if kk == "proven":
                        r.boolean()
                    elif kk in ("txid", "script"):
                        r.bytes_()
                    else:
                        r.uint()
                r.end_map()
            r.end_array()
        elif k == "op":
            r.text()
        elif k == "rawTx":
            r.bytes_()
        else:
            r.uint()
    r.end_map()
    r.end_of_input()
    ok("嵌套结构可完整解码", seen == ["op", "rawTx", "network", "prevouts", "opVersion", "inputIndex"],
       ",".join(seen))

    print("\n解码器严格性")
    for label, hexs, probe in [
        ("非最短整数", "1817", "uint"),
        ("非最短长度头", "59000568656c6c6f", "bytes"),
        ("不定长", "5f", "map"),
        ("标签 major 6", "c07432303133", "uint"),
        ("浮点", "fb3ff199999999999a", "uint"),
        ("undefined", "f7", "bool"),
        ("尾随字节", "0001", "map"),
        ("坏 UTF-8", "62c328", "text"),
        ("代理区码点", "63eda080", "text"),
        ("深度超限", "81" * 8, "array"),
        ("声明长度超输入", "590400", "bytes"),
        ("对数超上限", "a5616100", "map"),
    ]:
        def run(hexs=hexs, probe=probe):
            rd = CborReader(bytes.fromhex(hexs))
            if probe == "map":
                cnt = rd.begin_map()
                for _ in range(cnt):
                    rd.map_key()
                    rd.uint()
                rd.end_map()
            elif probe == "array":
                cnt = rd.begin_array()
                for _ in range(cnt):
                    rd.begin_array()
                rd.end_array()
            elif probe == "uint":
                rd.uint()
            elif probe == "bytes":
                rd.bytes_()
            elif probe == "text":
                rd.text()
            elif probe == "bool":
                rd.boolean()
            rd.end_of_input()
        expect_error(label, run)

    print("\n帧层")
    frame = R.encode_frame(0x10, 0x01, 7, b"vlp")
    ok("帧头 magic", frame[:2] == b"\xa5\x5a")
    ok("帧总长 = 11 + L + 4", len(frame) == 11 + len(b"vlp") + 4)
    r = R.FrameReader()
    got = r.feed(frame)
    ok("整帧往返", len(got) == 1 and got[0].payload == b"vlp")
    r = R.FrameReader()
    out = [f for i in range(len(frame)) for f in r.feed(frame[i : i + 1])]
    ok("逐字节喂入（断包）", len(out) == 1)
    a = R.encode_frame(0x10, 0x00, 1, b"a")
    b = R.encode_frame(0x11, 0x00, 2, b"bb")
    ok("粘包一次取两帧", len(R.FrameReader().feed(a + b)) == 2)
    r = R.FrameReader()
    out = r.feed(bytes([0, 0xFF, 0xA5, 0x00]) + a + b)
    ok("噪声前缀后恢复完整帧", len(out) == 2, f"resyncs={r.resyncs}")
    r = R.FrameReader()
    bad = bytearray(a)
    bad[-1] ^= 0xFF
    ok("CRC 错误丢弃", len(r.feed(bytes(bad))) == 0 and r.dropped == 1)
    r = R.FrameReader()
    ok("仅凭头拒绝超长负载",
       len(r.feed(bytes([0xA5, 0x5A, 1, 0x10, 0, 0, 0, 0, 0, 0xFF, 0xFF]))) == 0 and r.dropped == 1)
    ok("恰好 MAX_FRAME_PAYLOAD 被接受",
       len(R.FrameReader().feed(R.encode_frame(0x10, 0, 1, bytes(R.MAX_FRAME_PAYLOAD)))) == 1)
    expect_error("保留标志位", lambda: R.encode_frame(0x10, 0x08, 1, b""))
    expect_error("负载超上限", lambda: R.encode_frame(0x10, 0, 1, bytes(R.MAX_FRAME_PAYLOAD + 1)))
    ok("AAD 10 字节且大端",
       R.frame_aad(0x10, 0x01, 0x01020304, 0xAABBCCDD).hex() == "100101020304aabbccdd")

    print("\n握手与派生")
    ok("transcript 域标签 16 字节", len(R.DOMAIN_HANDSHAKE) == 16)
    ok("持有权域标签 17 字节", len(R.DOMAIN_POSSESSION) == 17)
    ok("配对域标签 19 字节", len(R.DOMAIN_PAIRING) == 19)
    ok("c2s/s2c 域标签不同",
       R.DOMAIN_C2S_KEY != R.DOMAIN_S2C_KEY and R.DOMAIN_C2S_NONCE != R.DOMAIN_S2C_NONCE)
    code = R.pairing_code(bytes(32))
    ok("配对码恰好 6 位十进制", len(code) == 6 and code.isdigit(), code)
    keys = R.derive_link_keys(bytes(32), bytes(32))
    ok("方向密钥不同", keys["c2sKey"] != keys["s2cKey"])
    ok("方向 nonce 不同", keys["c2sBaseNonce"] != keys["s2cBaseNonce"])

    print("\nLocal Secret v3")
    pub = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    priv = bytes(31) + b"\x01"
    key = R.local_secret_key(priv, pub, "storage.bucket-password")
    ok("派生密钥为公开可复算值",
       key.hex() == "8b9534f16d1eec1714c3c5642652d3eff0a9f7b72e5da4e9973d666e8b259112",
       key.hex())
    aad = R.local_secret_aad("storage.bucket-password", bytes(range(16)))
    ok("AAD 以信封 salt 结尾", aad.endswith(bytes(range(16))))
    scope = b"storage.bucket-password"
    ok("AAD 分隔符位置正确（prefix ‖ scope ‖ 0x00 ‖ salt）",
       aad[:26] == b"keymaster:local-secret:v3|" and
       aad[26:26 + len(scope)] == scope and
       aad[26 + len(scope)] == 0 and
       aad[27 + len(scope):] == bytes(range(16)),
       f"{len(aad)} 字节")
    ok("HKDF salt 是常量而非信封 salt",
       R.local_secret_key(priv, pub, "s").__len__() == 32 and
       R.local_secret_key(priv, pub, "s") != R.hkdf_sha256(
           priv, bytes(range(16)),
           pub.hex().encode() + b"\x00" + b"s", 32))
    expect_error("scope 超 95 字节", lambda: R.validate_scope("s" * 96))
    expect_error("scope 含控制字符", lambda: R.validate_scope("a\x07b"))
    expect_error("空 scope", lambda: R.validate_scope(""))
    expect_error("信封 salt 非 16 字节", lambda: R.local_secret_aad("s", bytes(15)))

    print("\nBSV P2PKH")
    mine = R.hash160(pub)
    ok("测试公钥地址",
       R.p2pkh_address(mine) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
       R.p2pkh_address(mine))
    tx = R.Tx(0, [R.TxIn(bytes(32), 0, b"", 0xFFFFFFFF)],
              [R.TxOut(90000, R.build_p2pkh_script(bytes(range(20)))),
               R.TxOut(95000, R.build_p2pkh_script(mine))], 0)
    raw = R.serialize_tx(tx)
    ok("交易可往返解析", R.parse_tx(raw).outputs[1].satoshis == 95000)
    prev = [R.PrevOut(bytes(32), 0, R.build_p2pkh_script(mine), 200000)]
    rev = R.review_tx(raw, prev, pub, 0)
    ok("费用为 15000 sat", rev.fee_sats == 15000, str(rev.fee_sats))
    ok("找零金额 95000", rev.change_sats == 95000)
    ok("付款总额 90000", rev.pay_total_sats == 90000)
    ok("sighash 长度 32", len(rev.sighash) == 32)
    expect_error("前序不属于本 Key",
                 lambda: R.review_tx(
                     raw, [R.PrevOut(bytes(32), 0, R.build_p2pkh_script(bytes(range(20))), 200000)],
                     pub, 0))
    expect_error("inputIndex 越界", lambda: R.review_tx(raw, prev, pub, 1))
    expect_error("缺前序证据", lambda: R.review_tx(raw, [], pub, 0))
    expect_error("rawTx 尾随字节", lambda: R.review_tx(raw + b"\x00", prev, pub, 0))
    wrong_version = R.serialize_tx(
        R.Tx(1, [R.TxIn(bytes(32), 0, b"", 0xFFFFFFFF)],
             [R.TxOut(90000, R.build_p2pkh_script(bytes(range(20)))),
              R.TxOut(95000, R.build_p2pkh_script(mine))], 0))
    expect_error("网络/版本非 0（仅 BSV mainnet）",
                 lambda: R.review_tx(wrong_version, prev, pub, 0))
    no_change = R.Tx(0, [R.TxIn(bytes(32), 0, b"", 0xFFFFFFFF)],
                     [R.TxOut(200000, R.build_p2pkh_script(bytes(range(20))))], 0)
    expect_error("无找零输出",
                 lambda: R.review_tx(R.serialize_tx(no_change), prev, pub, 0))

    print("\n承诺与域隔离")
    obj = CborWriter().begin_map(1).key("challenge").raw(bytes(32)).end_map().bytes()
    c1 = R.request_commitment("identity", 1, obj)
    c2 = R.request_commitment("identity", 1, obj + b"\x00")
    ok("承诺随输入变化", c1 != c2)
    ok("profileId 进承诺", R.request_commitment("identity", 1, obj)
       != R.request_commitment("bsv.p2pkh", 1, obj))
    ok("profileVersion 进承诺", R.request_commitment("identity", 1, obj)
       != R.request_commitment("identity", 2, obj))
    st_prove = R.identity_statement("prove", pub, 1, 3, bytes(32), "p")
    st_auth = R.identity_statement("authorize", pub, 1, 3, bytes(32), "p")
    ok("prove/authorize 域隔离", st_prove != st_auth)
    ok("持有权与身份声明域隔离",
       R.possession_statement(pub, 1, 2, 3, bytes(32)) != st_prove)

    print()
    if FAILURES:
        print(f"selfcheck: {len(FAILURES)} 项失败 — {', '.join(FAILURES)}")
        return 1
    print("selfcheck: 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())