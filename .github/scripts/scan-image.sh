#!/usr/bin/env bash
# 镜像漏洞扫描封装：调用内网扫描服务（主备自动切换），带超时与重试，判定结果写入 GITHUB_OUTPUT。
#
# 用法：scan-image.sh <完整镜像地址>
# 必需 env：GITHUB_OUTPUT
# 可覆盖 env：SCAN_API_PRIMARY（主服务，默认 http://192.168.141.42:8888）
#             SCAN_API_BACKUP（备服务，默认 http://192.168.25.100:8888）
#             SCAN_API（显式指定单一服务，跳过主备探测与切换，用于调试）
#             MAX_ATTEMPTS（单服务尝试次数，默认 3）、RETRY_DELAY（默认 30 秒）、SCAN_TIMEOUT（默认 300 秒）
#
# 主备策略（与 jaeger fix-image-vulns 技能的 scan-images.sh 保持一致）：
#   先探测主服务，可达则主为首选、备作后援；主不可达则降级用备；均不可达直接失败。
#   扫描阶段当前服务连续 MAX_ATTEMPTS 次失败后自动切换到下一个服务。
#
# 输出（GITHUB_OUTPUT）：
#   clean=true|false        os+lang 均为空即 true
#   vulns_md=<多行>         有漏洞时的 Markdown 明细表（按 CVE+包名去重）
set -euo pipefail

IMAGE_ADDR="${1:?用法: scan-image.sh <完整镜像地址>}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT 未设置}"
: "${SCAN_API_PRIMARY:=http://192.168.141.42:8888}"
: "${SCAN_API_BACKUP:=http://192.168.25.100:8888}"
: "${MAX_ATTEMPTS:=3}"
: "${RETRY_DELAY:=30}"
: "${SCAN_TIMEOUT:=300}"

# 服务是否可达：能返回任意 HTTP 状态码即算在线（连接拒绝/超时时 curl 输出 000）
probe_api() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 -m 10 "$1/" 2>/dev/null || true)"
  [ -n "$code" ] && [ "$code" != "000" ]
}

# 选定扫描服务顺序：优先主地址，失效切备（SCAN_API 显式指定时跳过探测）
APIS=()
if [ -n "${SCAN_API:-}" ]; then
  APIS=("$SCAN_API")
  echo "使用显式指定的扫描服务: $SCAN_API" >&2
elif probe_api "$SCAN_API_PRIMARY"; then
  APIS=("$SCAN_API_PRIMARY" "$SCAN_API_BACKUP")
  echo "使用主扫描服务: $SCAN_API_PRIMARY（备用: $SCAN_API_BACKUP）" >&2
elif probe_api "$SCAN_API_BACKUP"; then
  APIS=("$SCAN_API_BACKUP")
  echo "主扫描服务不可达（$SCAN_API_PRIMARY），切换到备用: $SCAN_API_BACKUP" >&2
else
  echo "主备扫描服务均不可达: $SCAN_API_PRIMARY / $SCAN_API_BACKUP" >&2
  exit 1
fi

# 镜像地址做 URL 编码后拼接扫描请求
encoded="$(jq -rn --arg v "$IMAGE_ADDR" '$v|@uri')"

# 内部扫描服务可能不稳定：每个服务单次超时上限 SCAN_TIMEOUT、最多 MAX_ATTEMPTS 次尝试，
# 连续失败后切换到下一个服务；单次成功标准 = HTTP 2xx 且响应可被 jq 解析出 os/lang 字段
resp=""
for api in "${APIS[@]}"; do
  url="${api}/image/vulnerability/custom?image_full_address=${encoded}&trivy_db_date=latest&severity=low&vulnerability_type=os%2Clibrary&version=v4.4.0"
  for i in $(seq 1 "$MAX_ATTEMPTS"); do
    echo "扫描尝试 ${i}/${MAX_ATTEMPTS}（服务 ${api}）: ${IMAGE_ADDR}" >&2
    if resp="$(curl -sS --fail --max-time "$SCAN_TIMEOUT" -H 'accept: application/json' "$url")" \
       && jq -e 'has("os") and has("lang")' <<<"$resp" >/dev/null 2>&1; then
      break 2
    fi
    resp=""
    if [ "$i" -lt "$MAX_ATTEMPTS" ]; then
      echo "本次扫描失败，${RETRY_DELAY}s 后重试" >&2
      sleep "$RETRY_DELAY"
    fi
  done
  echo "服务 ${api} 连续 ${MAX_ATTEMPTS} 次失败，尝试切换下一个服务" >&2
done

if [ -z "$resp" ]; then
  echo "所有扫描服务均失败: ${IMAGE_ADDR}" >&2
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
