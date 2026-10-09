"""VLP 独立参照实现 · 路径 A。

**本文件不是 SDK。** 它只用于生成 `test-vectors/` 的期望字节与摘要，
并作为 conformance 的第二条独立执行路径。

独立性要求（需求 §10 VLP-01）：

* 只用 Python 标准库。`hashlib` / `hmac` / `zlib.crc32` 覆盖
  SHA-256、SHA256d、HMAC-SHA256、HKDF-SHA256、RIPEMD-160、CRC-32/ISO-HDLC。
* **不 import** `sdk/typescript/`、`sdk/device/` 或 `conformance/` 的任何代码。
* AES-256-GCM 与 ECDSA 不在本文件实现：这两项由路径 B（Node，成熟实现）
  与 `test-vectors/crypto/` 中的公开标准向量共同覆盖，两条路径互不共享代码。

术语与规范：`spec/core/02-编码.md`（VLP-CBOR-1）、`spec/core/03-帧与消息.md`、
`spec/core/04-握手与链路.md`、`spec/core/05-承诺与授权.md`。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- 摘要原语


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """SHA-256d = SHA256(SHA256(x))。spec/security/01-密码套件.md §2"""
    return sha256(sha256(data))


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256。salt 为空时替换为 32 字节全零（与成熟实现一致）。"""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_sha256(salt, ikm)
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return okm[:length]


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def crc32_iso(data: bytes) -> int:
    """CRC-32/ISO-HDLC（反射多项式 0xEDB88320，init/末尾异或 0xFFFFFFFF）。
    spec/core/03-帧与消息.md §2"""
    return zlib.crc32(data) & 0xFFFFFFFF


# ------------------------------------------------------------ VLP-CBOR-1


class CborError(ValueError):
    """VLP-CBOR-1 编解码失败。规范要求一律拒绝，不得部分接受。"""


MAJ_UINT, MAJ_NEG, MAJ_BYTES, MAJ_TEXT, MAJ_ARRAY, MAJ_MAP = 0, 1, 2, 3, 4, 5

MAX_DEPTH = 6
MAX_KEY_LEN = 31
MAX_TOP_PAIRS = 24


def key_sort_token(key: str) -> tuple[int, bytes]:
    """VLP 键序：(字节长度, 字节序)。spec/core/02-编码.md §3.3"""
    raw = key.encode("utf-8")
    if not raw or len(raw) > MAX_KEY_LEN:
        raise CborError(f"key length out of range: {len(raw)}")
    return (len(raw), raw)


def _head(major: int, value: int) -> bytes:
    """最短整数头，参数大端。spec/core/02-编码.md §2.3"""
    if value < 0:
        raise CborError("negative head value")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", value)
    raise CborError("integer out of range")


class CborWriter:
    """严格编码器：自校验 map 对数、数组元素数、深度与缓冲。spec/core/02-编码.md §3.6"""

    def __init__(self) -> None:
        self._buf = bytearray()
        # 统一容器栈，每层一帧：map 用 dict，array 用 int（剩余元素数）。
        # 键序状态按层保存 —— 这是对已知实现缺陷的修复（0002 §1 B7）。
        self._stack: list[Any] = []

    # -- 内部 ------------------------------------------------------------
    def _take_value(self) -> None:
        """一个元素完成。只有栈顶是 array 时才消耗它的元素计数。"""
        if not self._stack:
            return
        top = self._stack[-1]
        if isinstance(top, int):
            top -= 1
            if top < 0:
                raise CborError("array element count exceeded")
            self._stack[-1] = top

    @property
    def depth(self) -> int:
        return len(self._stack)

    def _check_depth(self) -> None:
        if self.depth >= MAX_DEPTH:
            raise CborError(f"depth exceeds {MAX_DEPTH}")

    # -- map -------------------------------------------------------------
    def begin_map(self, pairs: int) -> "CborWriter":
        if not 0 <= pairs <= MAX_TOP_PAIRS:
            raise CborError(f"map pair count out of range: {pairs}")
        self._check_depth()
        self._buf += _head(MAJ_MAP, pairs)
        self._stack.append({"used": 0, "declared": pairs, "last": None})
        return self

    def key(self, key: str) -> "CborWriter":
        if not self._stack or not isinstance(self._stack[-1], dict):
            raise CborError("key outside map")
        frame = self._stack[-1]
        if frame["used"] >= frame["declared"]:
            raise CborError("more keys than declared pairs")
        token = key_sort_token(key)
        if frame["last"] is not None and token <= frame["last"]:
            raise CborError(f"key out of order or duplicated: {key}")
        frame["last"] = token
        frame["used"] += 1
        self._buf += _head(MAJ_TEXT, token[0]) + token[1]
        return self

    def end_map(self) -> "CborWriter":
        if not self._stack or not isinstance(self._stack[-1], dict):
            raise CborError("end_map without begin_map")
        frame = self._stack.pop()
        if frame["used"] != frame["declared"]:
            raise CborError(
                f"map pair count mismatch: wrote {frame['used']}, declared {frame['declared']}"
            )
        self._take_value()
        return self

    # -- array -----------------------------------------------------------
    def begin_array(self, count: int) -> "CborWriter":
        if count < 0:
            raise CborError("negative array count")
        self._check_depth()
        self._buf += _head(MAJ_ARRAY, count)
        self._stack.append(count)
        return self

    def end_array(self) -> "CborWriter":
        if not self._stack or not isinstance(self._stack[-1], int):
            raise CborError("end_array without begin_array")
        left = self._stack.pop()
        if left != 0:
            raise CborError(f"array count mismatch: {left} elements left")
        self._take_value()
        return self

    # -- 值 --------------------------------------------------------------
    def uint(self, value: int) -> "CborWriter":
        if value < 0:
            raise CborError("uint with negative value")
        self._buf += _head(MAJ_UINT, value)
        self._take_value()
        return self

    def int(self, value: int) -> "CborWriter":
        if value >= 0:
            return self.uint(value)
        self._buf += _head(MAJ_NEG, -1 - value)
        self._take_value()
        return self

    def raw(self, data: bytes) -> "CborWriter":
        self._buf += _head(MAJ_BYTES, len(data)) + data
        self._take_value()
        return self

    def text(self, value: str) -> "CborWriter":
        raw = value.encode("utf-8")
        self._buf += _head(MAJ_TEXT, len(raw)) + raw
        self._take_value()
        return self

    def boolean(self, value: bool) -> "CborWriter":
        self._buf += bytes([0xF5 if value else 0xF4])
        self._take_value()
        return self

    def null(self) -> "CborWriter":
        self._buf += bytes([0xF6])
        self._take_value()
        return self

    # -- 输出 ------------------------------------------------------------
    def bytes(self) -> bytes:
        if self._stack:
            raise CborError("unclosed container")
        return bytes(self._buf)

    def to_hex(self) -> str:
        return self.bytes().hex()

    @property
    def size(self) -> int:
        return len(self._buf)


class CborReader:
    """严格解码器：容器状态按层级栈。spec/core/02-编码.md §3.4"""

    def __init__(self, data: bytes) -> None:
        self._buf = data
        self._pos = 0
        self._stack: list[dict[str, Any]] = []

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._pos

    @property
    def ok(self) -> bool:
        try:
            self.end_of_input()
        except CborError:
            return False
        return True

    def _byte(self) -> int:
        if self._pos >= len(self._buf):
            raise CborError("truncated input")
        b = self._buf[self._pos]
        self._pos += 1
        return b

    def _take_value(self) -> None:
        if self._stack:
            top = self._stack[-1]
            if top["kind"] == "array":
                top["left"] -= 1
                if top["left"] < 0:
                    raise CborError("array element count exceeded")

    def _head(self) -> tuple[int, int]:
        ib = self._byte()
        major, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            value = ai
        elif ai == 24:
            value = self._byte()
            if value <= 23:
                raise CborError("non-minimal integer head")
        elif ai == 25:
            value = struct.unpack(">H", self._read(2))[0]
            if value <= 0xFF:
                raise CborError("non-minimal integer head")
        elif ai == 26:
            value = struct.unpack(">I", self._read(4))[0]
            if value <= 0xFFFF:
                raise CborError("non-minimal integer head")
        elif ai == 27:
            value = struct.unpack(">Q", self._read(8))[0]
            if value <= 0xFFFFFFFF:
                raise CborError("non-minimal integer head")
        else:
            raise CborError(f"forbidden additional info {ai}")
        return major, value

    def _read(self, n: int) -> bytes:
        if n > self.remaining:
            raise CborError("declared length exceeds remaining input")
        out = self._buf[self._pos : self._pos + n]
        self._pos += n
        return out

    def _check_depth(self) -> None:
        if len(self._stack) >= MAX_DEPTH:
            raise CborError(f"depth exceeds {MAX_DEPTH}")

    # -- 容器 ------------------------------------------------------------
    def begin_map(self) -> int:
        self._check_depth()
        major, pairs = self._head()
        if major != MAJ_MAP:
            raise CborError(f"expected map, got major {major}")
        if pairs > MAX_TOP_PAIRS:
            raise CborError(f"map pair count out of range: {pairs}")
        if pairs * 2 > self.remaining:
            raise CborError("declared pair count exceeds remaining input")
        self._stack.append({"kind": "map", "pairs": pairs, "left": pairs, "last": None})
        return pairs

    def map_key(self) -> str:
        if not self._stack or self._stack[-1]["kind"] != "map":
            raise CborError("map_key outside map")
        top = self._stack[-1]
        if top["left"] <= 0:
            raise CborError("more keys than declared pairs")
        major, length = self._head()
        if major != MAJ_TEXT:
            raise CborError(f"map key must be text, got major {major}")
        if not 1 <= length <= MAX_KEY_LEN:
            raise CborError(f"map key length out of range: {length}")
        raw = self._read(length)
        try:
            key = raw.decode("utf-8")
        except UnicodeDecodeError as exc:  # UTF-8 校验。§2.4
            raise CborError("map key is not well-formed UTF-8") from exc
        token = key_sort_token(key)
        if top["last"] is not None and token <= top["last"]:
            raise CborError(f"key out of order or duplicated: {key}")
        top["last"] = token
        top["left"] -= 1
        return key

    def end_map(self) -> None:
        if not self._stack or self._stack[-1]["kind"] != "map":
            raise CborError("end_map without begin_map")
        top = self._stack.pop()
        if top["left"] != 0:
            raise CborError(f"map has {top['left']} unread values")
        self._take_value()

    def begin_array(self) -> int:
        self._check_depth()
        major, count = self._head()
        if major != MAJ_ARRAY:
            raise CborError(f"expected array, got major {major}")
        if count > self.remaining:
            raise CborError("declared element count exceeds remaining input")
        self._stack.append({"kind": "array", "left": count})
        return count

    def end_array(self) -> None:
        if not self._stack or self._stack[-1]["kind"] != "array":
            raise CborError("end_array without begin_array")
        top = self._stack.pop()
        if top["left"] != 0:
            raise CborError(f"array has {top['left']} unread elements")
        self._take_value()

    # -- 标量 ------------------------------------------------------------
    def uint(self) -> int:
        major, value = self._head()
        if major != MAJ_UINT:
            raise CborError(f"expected unsigned int, got major {major}")
        self._take_value()
        return value

    def int(self) -> int:
        major, value = self._head()
        if major == MAJ_UINT:
            self._take_value()
            return value
        if major == MAJ_NEG:
            if value > 0x7FFFFFFFFFFFFFFF:
                raise CborError("negative integer out of int64 range")
            self._take_value()
            return -1 - value
        raise CborError(f"expected int, got major {major}")

    def bytes_(self) -> bytes:
        major, length = self._head()
        if major != MAJ_BYTES:
            raise CborError(f"expected byte string, got major {major}")
        out = self._read(length)
        self._take_value()
        return out

    def text(self) -> str:
        major, length = self._head()
        if major != MAJ_TEXT:
            raise CborError(f"expected text string, got major {major}")
        raw = self._read(length)
        try:
            out = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CborError("text string is not well-formed UTF-8") from exc
        self._take_value()
        return out

    def boolean(self) -> bool:
        b = self._byte()
        if b == 0xF5:
            out = True
        elif b == 0xF4:
            out = False
        else:
            raise CborError(f"forbidden simple value 0x{b:02X}")
        self._take_value()
        return out

    def null(self) -> None:
        b = self._byte()
        if b != 0xF6:
            raise CborError(f"expected null, got 0x{b:02X}")
        self._take_value()

    def end_of_input(self) -> None:
        if self._stack:
            raise CborError("unclosed container at end of input")
        if self.remaining != 0:
            raise CborError(f"{self.remaining} trailing byte(s)")


# ------------------------------------------------------------------ hex


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(text: str) -> bytes:
    """小写 hex 解码；拒绝奇数长度与非 hex 字符。spec/core/02-编码.md §5"""
    if len(text) % 2 != 0:
        raise ValueError("odd-length hex")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("non-hex character") from exc


# -------------------------------------------------------------- 帧层


MAGIC0, MAGIC1, VERSION = 0xA5, 0x5A, 1
FRAME_HEADER_LEN = 11
FRAME_TRAILER_LEN = 4
MAX_FRAME_PAYLOAD = 1024
MAX_MESSAGE = 896
MAX_SESSIONS = 2
MAX_PENDING_REQUESTS = 4
MAX_RESULT_CACHE = 8
MAX_SESSION_DECISIONS = 8


@dataclass
class Frame:
    type: int
    flags: int
    seq: int
    payload: bytes


def encode_frame(frame_type: int, flags: int, seq: int, payload: bytes) -> bytes:
    """帧编码。CRC 覆盖 [2, 11+L)，magic 不计入。spec/core/03-帧与消息.md §2"""
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise CborError(f"payload {len(payload)} exceeds MAX_FRAME_PAYLOAD {MAX_FRAME_PAYLOAD}")
    if flags & ~0x03:
        raise CborError(f"reserved flag bits set: 0x{flags:02X}")
    body = bytes([VERSION, frame_type, flags]) + struct.pack("<I", seq) + struct.pack("<H", len(payload))
    body += payload
    return bytes([MAGIC0, MAGIC1]) + body + struct.pack("<I", crc32_iso(body))


def frame_aad(frame_type: int, flags: int, seq: int, device_run_id: int) -> bytes:
    """10 字节 AAD，整数大端。spec/core/03-帧与消息.md §4.1"""
    return bytes([frame_type, flags]) + struct.pack(">I", seq) + struct.pack(">I", device_run_id)


class FrameReader:
    """字节流帧解析：处理断包、粘包、噪声与重同步。spec/core/03-帧与消息.md §2.3"""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.dropped = 0
        self.resyncs = 0

    @property
    def _capacity(self) -> int:
        return MAX_FRAME_PAYLOAD + FRAME_HEADER_LEN + FRAME_TRAILER_LEN

    def feed(self, data: bytes) -> list[Frame]:
        """喂入一段字节，返回本次可取出的全部完整帧。

        断包、粘包、噪声前缀都要能恢复：重同步后继续尝试解析后续字节，
        不能因为一次重同步就停止（否则噪声后的完整帧会被丢弃）。
        """
        self._buf += data
        out: list[Frame] = []
        while True:
            frame, progressed = self._take_buffered()
            if frame is not None:
                out.append(frame)
                continue
            if not progressed:
                break
        return out

    def _flush(self) -> None:
        self._buf.clear()
        self.resyncs += 1

    def _resync_one(self) -> None:
        """噪声前缀按字节重新同步，保留其后的完整帧。"""
        del self._buf[0]
        self.resyncs += 1

    def _take_buffered(self) -> tuple[Frame | None, bool]:
        """返回 (帧, 是否取得进展)。

        进展=True 表示缓冲区已改变（重同步或丢帧），调用方应继续尝试；
        进展=False 表示需要更多输入。
        """
        buf = self._buf
        if not buf:
            return None, False
        if buf[0] != MAGIC0:
            self._resync_one()
            return None, True
        if len(buf) < 2:
            return None, False
        if buf[1] != MAGIC1:
            self._resync_one()
            return None, True
        if len(buf) < FRAME_HEADER_LEN:
            return None, False
        if buf[2] != VERSION:
            self.dropped += 1
            self._flush()
            return None, True
        payload_len = struct.unpack("<H", bytes(buf[9:11]))[0]
        if payload_len > MAX_FRAME_PAYLOAD:
            self.dropped += 1
            self._flush()
            return None, True
        total = FRAME_HEADER_LEN + payload_len + FRAME_TRAILER_LEN
        if len(buf) < total:
            return None, False
        body = bytes(buf[2 : FRAME_HEADER_LEN + payload_len])
        expect = struct.unpack("<I", bytes(buf[total - 4 : total]))[0]
        if crc32_iso(body) != expect:
            self.dropped += 1
            self._flush()
            return None, True
        frame = Frame(
            type=buf[3],
            flags=buf[4],
            seq=struct.unpack("<I", bytes(buf[5:9]))[0],
            payload=bytes(buf[FRAME_HEADER_LEN : FRAME_HEADER_LEN + payload_len]),
        )
        del buf[:total]
        return frame, True


# ------------------------------------------------------------ 握手与链路

DOMAIN_HANDSHAKE = b"vlp:handshake:v1"
DOMAIN_PAIRING = b"vlp:link:pairing:v1"
DOMAIN_C2S_KEY = b"vlp:link:c2s:key:v1"
DOMAIN_C2S_NONCE = b"vlp:link:c2s:nonce:v1"
DOMAIN_S2C_KEY = b"vlp:link:s2c:key:v1"
DOMAIN_S2C_NONCE = b"vlp:link:s2c:nonce:v1"
DOMAIN_POSSESSION = b"vlp:possession:v1"
DOMAIN_COMMIT = b"vlp:commit:v1"
DOMAIN_CONTENT = b"vlp:content:v1"
DOMAIN_IDENTITY_PROVE = b"vlp:identity:prove:v1"
DOMAIN_IDENTITY_AUTHORIZE = b"vlp:identity:authorize:v1"
DOMAIN_MIGRATION_IMPORT = b"vlp:migration:import:v1"


def handshake_transcript(
    host_nonce: bytes,
    device_nonce: bytes,
    host_ephemeral: bytes,
    device_ephemeral: bytes,
    device_run_id: int,
    host_run_generation: int,
    wallet_generation: int,
    backend_generation: int,
    public_key: bytes,
) -> bytes:
    """194 字节输入，单次 SHA-256。spec/core/04-握手与链路.md §3.1"""
    buf = bytearray()
    buf += DOMAIN_HANDSHAKE
    buf += bytes([VERSION])
    buf += host_nonce
    buf += device_nonce
    buf += host_ephemeral
    buf += device_ephemeral
    buf += struct.pack(">I", device_run_id)
    buf += struct.pack(">I", host_run_generation)
    buf += struct.pack(">I", wallet_generation)
    buf += struct.pack(">I", backend_generation)
    buf += public_key
    return sha256(bytes(buf))


def derive_link_keys(shared: bytes, transcript: bytes) -> dict[str, bytes]:
    return {
        "c2sKey": hkdf_sha256(shared, transcript, DOMAIN_C2S_KEY, 32),
        "c2sBaseNonce": hkdf_sha256(shared, transcript, DOMAIN_C2S_NONCE, 12),
        "s2cKey": hkdf_sha256(shared, transcript, DOMAIN_S2C_KEY, 32),
        "s2cBaseNonce": hkdf_sha256(shared, transcript, DOMAIN_S2C_NONCE, 12),
    }


def pairing_code(transcript: bytes) -> str:
    """6 位十进制，最高位在前。spec/core/04-握手与链路.md §3.3

    24 位值先对 10^6 取模，保证恰好 6 位；因此有效熵约 19.9 位，
    这正是 6 位数字码的固有上限，不靠"多给几位"来假装更强。
    """
    h = sha256(DOMAIN_PAIRING + transcript)
    v = ((h[0] << 16) | (h[1] << 8) | h[2]) % 1_000_000
    return f"{v:06d}"


def possession_statement(
    public_key: bytes, device_run_id: int, host_run_generation: int, session_id: int, challenge: bytes
) -> bytes:
    """95 字节输入，SHA256d。spec/core/04-握手与链路.md §5.2"""
    buf = bytearray()
    buf += DOMAIN_POSSESSION
    buf += bytes([0])
    buf += public_key
    buf += struct.pack(">I", device_run_id)
    buf += struct.pack(">I", host_run_generation)
    buf += struct.pack(">I", session_id)
    buf += challenge
    return sha256d(bytes(buf))


# -------------------------------------------------------- 承诺与声明摘要


def request_commitment(profile_id: str, profile_version: int, commit_object: bytes) -> bytes:
    """spec/core/05-承诺与授权.md §2.1"""
    buf = bytearray()
    buf += DOMAIN_COMMIT
    buf += bytes([0])
    buf += profile_id.encode("utf-8")
    buf += bytes([0])
    buf += bytes([profile_version])
    buf += commit_object
    return sha256d(bytes(buf))


def identity_statement(
    purpose_class: str, public_key: bytes, session_id: int, session_epoch: int,
    challenge: bytes, purpose: str,
) -> bytes:
    domain = DOMAIN_IDENTITY_PROVE if purpose_class == "prove" else DOMAIN_IDENTITY_AUTHORIZE
    buf = bytearray()
    buf += domain
    buf += bytes([0])
    buf += public_key
    buf += struct.pack(">I", session_id)
    buf += bytes([session_epoch])
    buf += challenge
    buf += bytes([0])
    buf += purpose.encode("utf-8")
    return sha256d(bytes(buf))


def content_statement(purpose: str, digest_hex: str) -> bytes:
    """spec/profiles/05-content.md §3"""
    buf = bytearray()
    buf += DOMAIN_CONTENT
    buf += bytes([0])
    buf += purpose.encode("utf-8")
    buf += bytes([0])
    buf += digest_hex.encode("utf-8")
    return sha256d(bytes(buf))


def import_commitment(private_key: bytes) -> bytes:
    """spec/profiles/07-migration.md §4.2"""
    return sha256d(DOMAIN_MIGRATION_IMPORT + bytes([0]) + private_key)


# ----------------------------------------------------- Local Secret v3

LOCAL_SECRET_HKDF_SALT = b"keymaster.vault.local-secret.v3"
LOCAL_SECRET_AAD_PREFIX = b"keymaster:local-secret:v3|"
LOCAL_SECRET_KEY_SOURCE = "active-key-hkdf-v1"
LOCAL_SECRET_VERSION = 3


def local_secret_key(private_key: bytes, public_key: bytes, scope: str) -> bytes:
    """HKDF-SHA256(ikm=私钥, salt=常量, info=小写公钥hex ‖ 0x00 ‖ scope, L=32)"""
    info = to_hex(public_key).encode("utf-8") + bytes([0]) + scope.encode("utf-8")
    return hkdf_sha256(private_key, LOCAL_SECRET_HKDF_SALT, info, 32)


def local_secret_aad(scope: str, salt: bytes) -> bytes:
    """UTF8(前缀 ‖ scope) ‖ 0x00 ‖ salt(16)。信封 salt 只在这里出现。"""
    if len(salt) != 16:
        raise ValueError("envelope salt must be 16 bytes")
    return LOCAL_SECRET_AAD_PREFIX + scope.encode("utf-8") + bytes([0]) + salt


def validate_scope(scope: str) -> None:
    """1–95 字节；每字节 > 0x1F 且 ≠ 0x7F；良构 UTF-8。"""
    raw = scope.encode("utf-8")
    if not 1 <= len(raw) <= 95:
        raise ValueError(f"scope length {len(raw)} out of range 1..95")
    for b in raw:
        if b <= 0x1F or b == 0x7F:
            raise ValueError("scope contains control character")


# ---------------------------------------------------------- BSV 交易

SIGHASH_ALL_FORKID = 0x41
BSV_MAX_INPUTS = 4
BSV_MAX_OUTPUTS = 6
BSV_MAX_RAW_TX = 640
P2PKH_SCRIPT_LEN = 25
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(payload: bytes) -> str:
    n = int.from_bytes(payload, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    for byte in payload:
        if byte != 0:
            break
        out = "1" + out
    return out


def p2pkh_address(hash160_bytes: bytes) -> str:
    payload = bytes([0x00]) + hash160_bytes
    checksum = sha256d(payload)[:4]
    return b58encode(payload + checksum)


def build_p2pkh_script(hash160_bytes: bytes) -> bytes:
    return bytes([0x76, 0xA9, 0x14]) + hash160_bytes + bytes([0x88, 0xAC])


def is_p2pkh(script: bytes) -> bool:
    return (
        len(script) == P2PKH_SCRIPT_LEN
        and script[0] == 0x76
        and script[1] == 0xA9
        and script[2] == 0x14
        and script[23] == 0x88
        and script[24] == 0xAC
    )


def write_varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    b = data[pos]
    pos += 1
    if b < 0xFD:
        return b, pos
    if b == 0xFD:
        return struct.unpack("<H", data[pos : pos + 2])[0], pos + 2
    if b == 0xFE:
        return struct.unpack("<I", data[pos : pos + 4])[0], pos + 4
    return struct.unpack("<Q", data[pos : pos + 8])[0], pos + 8


@dataclass
class TxIn:
    txid: bytes
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFE


@dataclass
class TxOut:
    satoshis: int
    script: bytes


@dataclass
class Tx:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    lock_time: int


def serialize_tx(tx: Tx) -> bytes:
    out = bytearray(struct.pack("<I", tx.version))
    out += write_varint(len(tx.inputs))
    for i in tx.inputs:
        out += i.txid + struct.pack("<I", i.vout)
        out += write_varint(len(i.script_sig)) + i.script_sig
        out += struct.pack("<I", i.sequence)
    out += write_varint(len(tx.outputs))
    for o in tx.outputs:
        if o.satoshis < 0 or o.satoshis > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("output amount out of u64 range")
        out += struct.pack("<Q", o.satoshis) + write_varint(len(o.script)) + o.script
    out += struct.pack("<I", tx.lock_time)
    return bytes(out)


def parse_tx(raw: bytes) -> Tx:
    """严格反序列化：尾随字节即失败。溢出检查显式。"""
    if len(raw) > BSV_MAX_RAW_TX:
        raise ValueError(f"rawTx {len(raw)} exceeds limit {BSV_MAX_RAW_TX}")
    pos = 0
    version = struct.unpack("<I", raw[pos : pos + 4])[0]
    pos += 4
    n_in, pos = read_varint(raw, pos)
    if n_in < 1 or n_in > BSV_MAX_INPUTS:
        raise ValueError(f"input count {n_in} out of range 1..{BSV_MAX_INPUTS}")
    inputs = []
    for _ in range(n_in):
        txid = raw[pos : pos + 32]
        pos += 32
        vout = struct.unpack("<I", raw[pos : pos + 4])[0]
        pos += 4
        ss_len, pos = read_varint(raw, pos)
        if ss_len > 1000 or pos + ss_len > len(raw):
            raise ValueError("scriptSig length out of range")
        script_sig = raw[pos : pos + ss_len]
        pos += ss_len
        sequence = struct.unpack("<I", raw[pos : pos + 4])[0]
        pos += 4
        inputs.append(TxIn(txid, vout, script_sig, sequence))
    n_out, pos = read_varint(raw, pos)
    if n_out < 1 or n_out > BSV_MAX_OUTPUTS:
        raise ValueError(f"output count {n_out} out of range 1..{BSV_MAX_OUTPUTS}")
    outputs = []
    total_out = 0
    for _ in range(n_out):
        satoshis = struct.unpack("<Q", raw[pos : pos + 8])[0]
        pos += 8
        script_len, pos = read_varint(raw, pos)
        if not 1 <= script_len <= 128 or pos + script_len > len(raw):
            raise ValueError("output script length out of range")
        script = raw[pos : pos + script_len]
        pos += script_len
        if total_out > 0xFFFFFFFFFFFFFFFF - satoshis:
            raise ValueError("total output amount overflows u64")
        total_out += satoshis
        outputs.append(TxOut(satoshis, script))
    if pos + 4 != len(raw):
        raise ValueError("trailing bytes in rawTx")
    lock_time = struct.unpack("<I", raw[pos : pos + 4])[0]
    return Tx(version, inputs, outputs, lock_time)


@dataclass
class PrevOut:
    txid: bytes
    vout: int
    script: bytes
    satoshis: int
    proven: bool = False


@dataclass
class TxReview:
    sighash: bytes
    sighash_type: int
    fee_sats: int
    change_sats: int
    pay_total_sats: int
    change_address: str
    pays: list[tuple[int, str]]
    change_outputs: list[int]


def bip143_sighash(tx: Tx, input_index: int, prevout_amount: int, script_code: bytes) -> bytes:
    """BIP143 SIGHASH_ALL|SIGHASH_FORKID。spec/profiles/02-bsv-p2pkh.md §3"""
    hash_prevouts = sha256d(
        b"".join(i.txid + struct.pack("<I", i.vout) for i in tx.inputs)
    )
    hash_sequence = sha256d(b"".join(struct.pack("<I", i.sequence) for i in tx.inputs))
    hash_outputs = sha256d(
        b"".join(
            struct.pack("<Q", o.satoshis) + write_varint(len(o.script)) + o.script
            for o in tx.outputs
        )
    )
    target = tx.inputs[input_index]
    preimage = bytearray()
    preimage += struct.pack("<I", tx.version)
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += target.txid
    preimage += struct.pack("<I", target.vout)
    preimage += write_varint(len(script_code))
    preimage += script_code
    preimage += struct.pack("<Q", prevout_amount)
    preimage += struct.pack("<I", target.sequence)
    preimage += hash_outputs
    preimage += struct.pack("<I", tx.lock_time)
    preimage += struct.pack("<I", SIGHASH_ALL_FORKID)
    return sha256d(bytes(preimage))


def review_tx(raw_tx: bytes, prevouts: list[PrevOut], public_key: bytes, input_index: int) -> TxReview:
    """设备侧验证顺序。spec/profiles/02-bsv-p2pkh.md §4"""
    tx = parse_tx(raw_tx)
    if tx.version != 0:
        raise ValueError("network/version must be 0 (BSV mainnet)")
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("inputIndex out of range")
    evidence = {(p.txid, p.vout): p for p in prevouts}
    total_in = 0
    for i in tx.inputs:
        key = (i.txid, i.vout)
        if key not in evidence:
            raise ValueError(f"missing prevout evidence for input {i.vout}")
        ev = evidence[key]
        if not is_p2pkh(ev.script):
            raise ValueError("prevout script is not standard P2PKH")
        if total_in > 0xFFFFFFFFFFFFFFFF - ev.satoshis:
            raise ValueError("total input amount overflows u64")
        total_in += ev.satoshis
    total_out = sum(o.satoshis for o in tx.outputs)
    if total_in < total_out:
        raise ValueError("totalOut exceeds totalIn")
    mine = hash160(public_key)
    target = tx.inputs[input_index]
    target_ev = evidence[(target.txid, target.vout)]
    if target_ev.script[3:23] != mine:
        raise ValueError("signed input is not owned by this key")
    pays: list[tuple[int, str]] = []
    change_outputs: list[int] = []
    change_sats = 0
    for idx, o in enumerate(tx.outputs):
        if not is_p2pkh(o.script):
            raise ValueError(f"output {idx} script is not standard P2PKH")
        addr = p2pkh_address(o.script[3:23])
        if o.script[3:23] == mine:
            change_outputs.append(idx)
            change_sats += o.satoshis
        else:
            pays.append((o.satoshis, addr))
    if not pays:
        raise ValueError("no payment output")
    if not change_outputs:
        raise ValueError("no change output owned by this key")
    sighash = bip143_sighash(tx, input_index, target_ev.satoshis, target_ev.script)
    return TxReview(
        sighash=sighash,
        sighash_type=SIGHASH_ALL_FORKID,
        fee_sats=total_in - total_out,
        change_sats=change_sats,
        pay_total_sats=total_out - change_sats,
        change_address=p2pkh_address(mine),
        pays=pays,
        change_outputs=change_outputs,
    )