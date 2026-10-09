#!/usr/bin/env bash
# VLP 复现入口。
#
# 全部命令固定、无网络依赖、无隐藏步骤。缺工具时明确失败或记为不可验证，
# 绝不静默输出「兼容通过」。
#
#   ./scripts/verify.sh          生成向量 + 校验向量新鲜度 + 跑 conformance
#   ./scripts/verify.sh --check  只校验，不写文件（CI 用）
set -uo pipefail

cd "$(dirname "$0")/.."

MODE="${1:-generate}"
PY="${PYTHON:-python3}"
NODE="${NODE:-node}"
FAILED=0

step() { printf '\n=== %s ===\n' "$1"; }
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '缺失工具 %s —— 不输出兼容通过\n' "$1"
    exit 2
  fi
}

need "$PY"
need "$NODE"

printf 'python3 : %s\n' "$("$PY" --version 2>&1)"
printf 'node    : %s\n' "$("$NODE" --version)"

step "1/4 参考实现自检（路径 A，Python 标准库）"
if ! "$PY" tools/refgen/selfcheck.py; then FAILED=1; fi

step "2/4 规范向量生成（路径 A 独立计算期望值）"
if [ "$MODE" = "--check" ]; then
  if ! "$PY" tools/refgen/generate_vectors.py --check; then FAILED=1; fi
else
  if ! "$PY" tools/refgen/generate_vectors.py; then FAILED=1; fi
fi

step "3/4 参照实现一致性（路径 A 复核路径 B 的等价断言）"
if ! "$PY" tools/refgen/crosscheck.py; then FAILED=1; fi

step "4/4 合规运行（路径 B，Node 成熟密码实现实际执行）"
if ! "$NODE" conformance/run.js; then FAILED=1; fi

printf '\n'
if [ "$FAILED" -ne 0 ]; then
  printf 'verify.sh: 存在失败项 —— 不输出兼容通过\n'
  exit 1
fi
printf 'verify.sh: 全部通过（注意 unsupported 项表示本轮未实施，非已验证）\n'