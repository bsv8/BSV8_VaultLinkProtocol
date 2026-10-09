#!/usr/bin/env python3
"""路径 A：Python 标准库/既有严格编码器，独立计算 v2 的规范字节与 BIP143 期望值。"""
import sys, json, hashlib, struct
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/refgen'))
from vlp_ref import CborWriter, sha256, sha256d, hkdf_sha256, parse_tx, bip143_sighash

def cbor(v):
    w = CborWriter()
    def write(v):
        if v is None: w.null()
        elif isinstance(v, bool): w.boolean(v)
        elif isinstance(v, int): w.int(v)
        elif isinstance(v, bytes): w.raw(v)
        elif isinstance(v, str): w.text(v)
        elif isinstance(v, list):
            w.begin_array(len(v))
            for x in v: write(x)
            w.end_array()
        else:
            w.begin_map(len(v))
            for k in sorted(v, key=lambda k: (len(k.encode()), k.encode())):
                w.key(k); write(v[k])
            w.end_map()
    write(v)
    return w.bytes()

pub=bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
hello=dict(hostEph=bytes(range(32)),hostNonce=bytes(range(32,64)),protocolVersion=2,capabilities=[0x221],walletGeneration=1,backendGeneration=2,hostRunGeneration=3)
ack=dict(deviceEph=bytes(range(64,96)),deviceNonce=bytes(range(96,128)),publicKey=pub,deviceRunId=4,connectionId=5,protocolVersion=2,capabilities=[0x221])
t=sha256(b'vlp:handshake:v2\0'+cbor(dict(hello=hello,ack=ack)))
shared=bytes(range(32))
keys={}
for d in ['c2s','s2c']:
    for label,n in [('key',32),('nonce',12)]: keys[d+'-'+label]=hkdf_sha256(shared,t,('vlp:link:'+d+':'+label+':v2').encode(),n).hex()
h=sha256(b'vlp:link:pairing:v2'+t)
script=bytes.fromhex('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')
raw=struct.pack('<I',2)+b'\x01'+bytes(range(32))+struct.pack('<I',0)+b'\0'+struct.pack('<I',0x12345678)+b'\x01'+struct.pack('<Q',300)+bytes([len(script)])+script+struct.pack('<I',4)
vector=dict(protocolVersion=2,helloHex=cbor(hello).hex(),ackHex=cbor(ack).hex(),transcript=t.hex(),pairingCode=f'{int.from_bytes(h[:3],"big")%1000000:06d}',sharedHex=shared.hex(),keys=keys,bip143=dict(rawHex=raw.hex(),scriptHex=script.hex(),inputAmount='1000',digest=bip143_sighash(parse_tx(raw),0,1000,script).hex()))
file=ROOT/'test-vectors/v2/reference.json'
text=json.dumps(vector,ensure_ascii=False,indent=2)+'\n'
if '--check' in sys.argv:
    if not file.exists() or file.read_text()!=text: raise SystemExit('v2 reference vectors stale')
else:
    file.parent.mkdir(exist_ok=True);file.write_text(text)
print('v2 independent Python vectors: current')
