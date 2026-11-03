#!/usr/bin/env bash
# 交叉构建 Windows 版（在 Linux/macOS 上执行）：需要 Go 1.23+
set -e
cd "$(dirname "$0")"
mkdir -p dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -H windowsgui" -o "dist/免费公益节点面板.exe" .
echo "构建完成： dist/免费公益节点面板.exe"
