#!/usr/bin/env bash
# v2 实现检查；不刷新旧 v1 向量，不把软件字节管道报告成 USB 真机。
set -euo pipefail
cd "$(dirname "$0")/.."
python3 Coding/BSV8_VaultLinkProtocol/test/refgen.py --check
cd Coding/BSV8_VaultLinkProtocol
npm run test
