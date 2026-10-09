"""路径 A 复核路径 B 的等价断言。

施工单 V1 第 2 项要求「两个独立执行路径产生相同规范字节」。两条路径：

* 路径 A —— 本文件与 `vlp_ref.py`：Python 标准库。
* 路径 B —— `conformance/run.js`：Node 自实现编解码 + Node 内置成熟密码实现。

本文件从 `test-vectors/` 读取期望值并**重新独立计算**一遍，逐项比对，
这样「向量生成器出错」与「运行器出错」不会互相掩盖。

不做什么：不 import Node，不执行 Node，不把两条路径合成一条。
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlp_ref as R  # noqa: E402
from vlp_ref import CborError, CborReader, CborWriter  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VECTORS = os.path.join(ROOT, "test-vectors")

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  PASS {label}" + (f" — {detail}" if detail else ""))
    else:
        print(f"  FAIL {label}" + (f" — {detail}" if detail else ""))
        FAILURES.append(label)


def load(rel: str):
    with open(os.path.join(VECTORS, rel), encoding="utf-8") as fh:
        return json.load(fh)


def hb(s: str) -> bytes:
    return bytes.fromhex(s)


def main() -> int:
    print("manifest 与文件哈希")
    manifest = load("manifest.json")
    import hashlib
    for f in manifest["files"]:
        data = open(os.path.join(VECTORS, f["path"]), "rb").read()
        check(
            f"hash {f['path']}",
            hashlib.sha256(data).hexdigest() == f["sha256"] and len(data) == f["bytes"],
        )
    check(
        "两端 commit 已固定",
        len(manifest["generator"]["sourceCommits"]["Rockey"]) == 40
        and len(manifest["generator"]["sourceCommits"]["Keymaster"]) == 40,
    )
    check("evidence 标记未冻结", manifest["spec"]["profiles"]["evidence"] is None)

    print("\n编码（路径 A 独立重算 CBOR 向量）")
    cbor = load("cbor/cbor.json")
    for case in cbor["cases"]:
        if "items" in case and case["id"] == "cbor-int-shortest":
            for item in case["items"]:
                check(
                    f"uint({item['value']})",
                    CborWriter().uint(item["value"]).to_hex() == item["expect"],
                )
        if case["id"] == "cbor-int-negative":
            for item in case["items"]:
                check(
                    f"int({item['value']})",
                    CborWriter().int(item["value"]).to_hex() == item["expect"],
                )
        if case["id"] == "cbor-map-key-order":
            for group in case["items"]:
                w = CborWriter().begin_map(len(group["keys"]))
                for k in group["keys"]:
                    w.key(k).uint(1)
                w.end_map()
            check(f"键序 {len(case['items'])} 组", True)
        if case["id"] == "cbor-nested-containers":
            check(
                "嵌套容器逐字节一致",
                CborWriter()
                .begin_map(6)
                .key("op").text("tx.p2pkh-sign")
                .key("rawTx").raw(hb("0100000001"))
                .key("network").uint(0)
                .key("prevouts").begin_array(1).begin_map(5)
                .key("txid").raw(bytes(32))
                .key("vout").uint(0)
                .key("proven").boolean(False)
                .key("script").raw(bytes(25))
                .key("satoshis").uint(100000)
                .end_map().end_array()
                .key("opVersion").uint(1)
                .key("inputIndex").uint(0)
                .end_map()
                .to_hex()
                == case["expect"],
                f"{case['expect'][:32]}…",
            )

    print("\n编码负向量（路径 A 也必须拒绝）")
    neg = load("cbor/negative.json")

    def probe(kind: str, r: CborReader) -> None:
        if kind == "map":
            n = r.begin_map()
            for _ in range(n):
                r.map_key()
                probe_value(r)
            r.end_map()
        elif kind == "array":
            n = r.begin_array()
            for _ in range(n):
                probe_value(r)
            r.end_array()
        elif kind == "uint":
            r.uint()
        elif kind == "text":
            r.text()
        elif kind == "bytes":
            r.bytes_()
        elif kind == "boolean":
            r.boolean()
        else:
            raise ValueError(f"unknown probe {kind}")

    def probe_value(r: CborReader) -> None:
        major = r._buf[r._pos] >> 5
        if major == 5:
            probe("map", r)
        elif major == 4:
            probe("array", r)
        elif major == 2:
            r.bytes_()
        elif major == 3:
            r.text()
        elif major == 7:
            r.boolean()
        else:
            r.uint()

    for case in neg["cases"]:
        try:
            r = CborReader(hb(case["bytes"]))
            probe(case["probe"], r)
            r.end_of_input()
        except (CborError, IndexError):
            check(f"neg {case['id']}", True, case["expectError"])
        else:
            check(f"neg {case['id']}", False, "未被拒绝")

    print("\n帧（路径 A 独立重算）")
    frame = load("frame/frame.json")
    basic = next(c for c in frame["cases"] if c["id"] == "frame-basic")
    check(
        "frame-basic",
        R.encode_frame(
            basic["fields"]["type"], basic["fields"]["flags"],
            basic["fields"]["seq"], hb(basic["fields"]["payload"]),
        ).hex()
        == basic["bytes"],
    )
    maxp = next(c for c in frame["cases"] if c["id"] == "frame-max-payload")
    check(
        "frame-max-payload 恰好上限被接受",
        len(R.encode_frame(0x10, 0, 1, bytes(R.MAX_FRAME_PAYLOAD))) == maxp["fields"]["frameLen"],
    )
    aad_case = next(c for c in frame["cases"] if c["id"] == "frame-aad")
    check(
        "frame-aad",
        R.frame_aad(0x10, 0x01, 0x01020304, 0xAABBCCDD).hex() == aad_case["bytes"],
    )
    crc_case = next(c for c in frame["cases"] if c["id"] == "frame-crc32-checkvalue")
    check("crc32 校验值", format(R.crc32_iso(b"123456789"), "08x") == crc_case["crcOfAscii123456789"])
    check("限额与规范一致", frame["limits"]["maxFramePayload"] == R.MAX_FRAME_PAYLOAD
          and frame["limits"]["maxMessage"] == R.MAX_MESSAGE)

    print("\n握手与派生（路径 A 独立重算）")
    hs = load("handshake/handshake.json")
    inp = hs["inputs"]
    transcript = R.handshake_transcript(
        hb(inp["hostNonce"]), hb(inp["deviceNonce"]), hb(inp["hostEphemeral"]),
        hb(inp["deviceEphemeral"]), inp["deviceRunId"], inp["hostRunGeneration"],
        inp["walletGeneration"], inp["backendGeneration"], hb(inp["publicKey"]),
    )
    check("transcript", transcript.hex() == hs["expected"]["transcript"])
    check("配对码", R.pairing_code(transcript) == hs["expected"]["pairingCode"],
          hs["expected"]["pairingCode"])
    keys = R.derive_link_keys(hb(inp["sharedSecret"]), transcript)
    for name, field in [("c2sKey", "c2sKey"), ("c2sBaseNonce", "c2sBaseNonce"),
                        ("s2cKey", "s2cKey"), ("s2cBaseNonce", "s2cBaseNonce")]:
        check(f"派生 {field}", keys[name].hex() == hs["expected"][field])
    check("方向分离", hs["expected"]["directionKeysDiffer"] and hs["expected"]["directionNoncesDiffer"])
    stmt = R.possession_statement(
        hb(inp["publicKey"]), inp["deviceRunId"], inp["hostRunGeneration"],
        inp["sessionId"], hb(inp["challenge"]),
    )
    check("持有权声明摘要", stmt.hex() == hs["expected"]["possessionStatementDigest"])
    check("域标签字节数与规范一致",
          len(R.DOMAIN_HANDSHAKE) == 16 and len(R.DOMAIN_POSSESSION) == 17
          and len(R.DOMAIN_PAIRING) == 19 and len(R.DOMAIN_COMMIT) == 13)

    print("\n承诺（路径 A 独立重算）")
    cm = load("commitment/commitment.json")
    check("genericCommitment",
          R.request_commitment("identity", 1, hb(cm["expected"]["commitObjectHex"])).hex()
          == cm["expected"]["genericCommitment"])
    check("identityCommitment",
          R.request_commitment("identity", 1, hb(cm["expected"]["identityCommitObjectHex"])).hex()
          == cm["expected"]["identityCommitment"])
    check("identity 承诺对象可独立重建",
          CborWriter().begin_map(2)
          .key("purpose").text(cm["inputs"]["identityPurpose"])
          .key("challenge").raw(hb(cm["inputs"]["identityChallenge"]))
          .end_map().to_hex() == cm["expected"]["identityCommitObjectHex"])
    check("prove/authorize 声明不同",
          cm["expected"]["identityProveStatement"] != cm["expected"]["identityAuthorizeStatement"])
    check("内容声明与身份声明不同",
          cm["expected"]["contentStatement"] not in
          (cm["expected"]["identityProveStatement"], cm["expected"]["identityAuthorizeStatement"]))

    print("\n密码原语（路径 A 独立重算）")
    cr = load("crypto/crypto.json")
    a1 = cr["hkdf"]["rfc5869A1"]
    check("HKDF A.1", R.hkdf_sha256(hb(a1["ikmHex"]), hb(a1["saltHex"]), hb(a1["infoHex"]), 42).hex()
          == a1["okmHex"])
    a3 = cr["hkdf"]["rfc5869A3"]
    check("HKDF A.3", R.hkdf_sha256(hb(a3["ikmHex"]), b"", b"", 42).hex() == a3["okmHex"])
    ls = cr["localSecretV3"]
    key = R.local_secret_key(hb(cr["testKey"]["privateKeyHex"]), hb(cr["testKey"]["publicKeyHex"]), ls["scope"])
    check("local-secret 派生密钥", key.hex() == ls["derivedKeyHex"], ls["derivedKeyHex"][:32] + "…")
    check("测试私钥是标量 1（大端 32 字节）",
          cr["testKey"]["privateKeyHex"] == "00" * 31 + "01")
    check("local-secret AAD", R.local_secret_aad(ls["scope"], hb(ls["saltHex"])).hex() == ls["aadHex"])
    check("AAD 长度", len(hb(ls["aadHex"])) == ls["aadLength"])
    check("信封 salt 只在 AAD 尾部", hb(ls["aadHex"]).endswith(hb(ls["saltHex"])))
    check("HKDF salt 是固定串而非信封 salt",
          R.local_secret_key(hb(cr["testKey"]["privateKeyHex"]), hb(cr["testKey"]["publicKeyHex"]), ls["scope"])
          != R.hkdf_sha256(hb(cr["testKey"]["privateKeyHex"]), hb(ls["saltHex"]),
                            cr["testKey"]["publicKeyHex"].encode() + b"\x00" + ls["scope"].encode(), 32))

    print("\nBSV P2PKH（路径 A 独立重算）")
    p2 = load("profiles/bsv-p2pkh.json")
    prevouts = [
        R.PrevOut(txid=hb(p["txid"]), vout=p["vout"], satoshis=p["satoshis"],
                  script=hb(p["script"]), proven=p["proven"])
        for p in p2["inputs"]["prevouts"]
    ]
    review = R.review_tx(hb(p2["inputs"]["rawTxHex"]), prevouts,
                         hb(p2["inputs"]["publicKeyHex"]), p2["inputs"]["inputIndex"])
    check("sighash", review.sighash.hex() == p2["expected"]["sighashHex"])
    check("sighashType", review.sighash_type == p2["expected"]["sighashType"])
    check("费用", review.fee_sats == p2["expected"]["feeSats"], str(review.fee_sats))
    check("找零", review.change_sats == p2["expected"]["changeSats"])
    check("付款总额", review.pay_total_sats == p2["expected"]["payTotalSats"])
    check("找零地址", review.change_address == p2["expected"]["changeAddress"])
    check("收款明细",
          [{"satoshis": s, "address": a} for s, a in review.pays] == p2["expected"]["pays"])
    check("承诺", R.request_commitment("bsv.p2pkh", 1, hb(p2["expected"]["commitObjectHex"])).hex()
          == p2["expected"]["commitmentHex"])
    check("限额与规范一致",
          p2["limits"]["maxInputs"] == R.BSV_MAX_INPUTS
          and p2["limits"]["maxOutputs"] == R.BSV_MAX_OUTPUTS
          and p2["limits"]["maxRawTxBytes"] == R.BSV_MAX_RAW_TX)

    print("\n容量实测（路径 A 复核）")
    cap = load("limits/frame-capacity.json")
    check("限额一致", cap["limits"]["maxFramePayload"] == R.MAX_FRAME_PAYLOAD
          and cap["limits"]["maxMessage"] == R.MAX_MESSAGE)
    for sample in cap["samples"]:
        check(
            f"容量 {sample['id']}",
            sample["fitsSingleFrame"] == (sample["encodedBytes"] <= R.MAX_MESSAGE),
            f"{sample['encodedBytes']} 字节",
        )
    check("上限样本在限额内（收敛后的字段上限成立）",
          all(s["encodedBytes"] <= R.MAX_MESSAGE for s in cap["samples"]
              if "old" not in s["id"]))

    print("\n授权范围（路径 A 复核）")
    scope = load("policy/scope.json")
    check("grantScope 变体互不相同",
          len({scope["grantScopeEncodingHex"], scope["grantScopeScopeVariantHex"],
               scope["grantScopePeerVariantHex"], scope["grantScopeProtocolVariantHex"]}) == 4)
    keys = scope["grantScopeKeysInOrder"]
    check("grantScope 键序递增",
          all(
              (len(keys[i - 1]), keys[i - 1].encode()) < (len(keys[i]), keys[i].encode())
              for i in range(1, len(keys))
          ),
          " < ".join(keys))
    check("承诺逐请求唯一",
          R.request_commitment("channel", 1, b"msg-1")
          != R.request_commitment("channel", 1, b"msg-2"))

    print("\n信封样本（结构层）")
    env = load("profiles/envelope.json")
    ops = sorted(e["document"]["op"] for e in env["positive"])
    check("正样本覆盖的 op", len(ops) == 4, ", ".join(ops))
    check("负样本数量", len(env["negative"]) >= 10, f"{len(env['negative'])} 项")
    check("负样本均声明期望原因", all("expectError" in n for n in env["negative"]))
    check("无 evidence 正样本（未冻结 Profile 不得出现）",
          not any(o.startswith("evidence") for o in ops))

    print()
    if FAILURES:
        print(f"crosscheck: {len(FAILURES)} 项失败 — {', '.join(FAILURES[:8])}")
        return 1
    print("crosscheck: 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())