#!/usr/bin/env bash
# 镜像漏洞扫描封装：调用内部扫描服务，带超时与重试，判定结果写入 GITHUB_OUTPUT。
#
# 用法：scan-image.sh <完整镜像地址>
# 必需 env：SCAN_API、GITHUB_OUTPUT
# 可覆盖 env：MAX_ATTEMPTS（默认 3）、RETRY_DELAY（默认 30 秒）、SCAN_TIMEOUT（默认 300 秒）
#
# 输出（GITHUB_OUTPUT）：
#   clean=true|false        os+lang 均为空即 true
#   vulns_md=<多行>         有漏洞时的 Markdown 明细表（按 CVE+包名去重）
set -euo pipefail

IMAGE_ADDR="${1:?用法: scan-image.sh <完整镜像地址>}"
: "${SCAN_API:?SCAN_API 未设置}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT 未设置}"
: "${MAX_ATTEMPTS:=3}"
: "${RETRY_DELAY:=30}"
: "${SCAN_TIMEOUT:=300}"

# 镜像地址做 URL 编码后拼接扫描请求
encoded="$(jq -rn --arg v "$IMAGE_ADDR" '$v|@uri')"
url="${SCAN_API}/image/vulnerability/custom?image_full_address=${encoded}&trivy_db_date=latest&severity=low&vulnerability_type=os%2Clibrary&version=v4.4.0"

# 内部扫描服务可能不稳定：单次超时上限 SCAN_TIMEOUT，最多 MAX_ATTEMPTS 次尝试；
# 单次成功标准 = HTTP 2xx 且响应可被 jq 解析出 os/lang 字段
resp=""
for i in $(seq 1 "$MAX_ATTEMPTS"); do
  echo "扫描尝试 ${i}/${MAX_ATTEMPTS}: ${IMAGE_ADDR}" >&2
  if resp="$(curl -sS --fail --max-time "$SCAN_TIMEOUT" -H 'accept: application/json' "$url")" \
     && jq -e 'has("os") and has("lang")' <<<"$resp" >/dev/null 2>&1; then
    break
  fi
  resp=""
  if [ "$i" -lt "$MAX_ATTEMPTS" ]; then
    echo "本次扫描失败，${RETRY_DELAY}s 后重试" >&2
    sleep "$RETRY_DELAY"
  fi
done

if [ -z "$resp" ]; then
  echo "扫描服务连续 ${MAX_ATTEMPTS} 次失败: ${IMAGE_ADDR}" >&2
  exit 1
fi

count="$(jq '((.os // []) + (.lang // [])) | length' <<<"$resp")"
if [ "$count" -eq 0 ]; then
  echo "clean=true" >> "$GITHUB_OUTPUT"
  echo "镜像无漏洞: ${IMAGE_ADDR}" >&2
else
  echo "clean=false" >> "$GITHUB_OUTPUT"
  # 生成去重后的 Markdown 明细表（多行 output 用 heredoc 分隔符语法，分隔符加进程号防注入）
  {
    echo "vulns_md<<EOF_VULNS_$$"
    echo "| CVE | 包名 | 当前版本 | 修复版本 | 严重度 |"
    echo "| --- | --- | --- | --- | --- |"
    jq -r '((.os // []) + (.lang // []))
      | unique_by(.VulnerabilityID + "/" + .PkgName)
      | .[] | "| \(.VulnerabilityID) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion) | \(.Severity) |"' <<<"$resp"
    echo "EOF_VULNS_$$"
  } >> "$GITHUB_OUTPUT"
  echo "发现 ${count} 条漏洞记录（去重前）: ${IMAGE_ADDR}" >&2
fi
