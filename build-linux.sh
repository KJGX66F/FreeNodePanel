#!/usr/bin/env bash
# 交叉构建 Linux 版（VPS / 软路由托管用，issue #9）
# 产物：dist/FreeNodePanel-linux-amd64 与 dist/FreeNodePanel-linux-arm64
# （amd64 给 x86 VPS，arm64 给树莓派 / ARM 软路由）
# 前置：Go 1.23+。用法：./build-linux.sh
set -e
cd "$(dirname "$0")"
mkdir -p dist
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
    go build -trimpath -ldflags "-s -w" -o "dist/FreeNodePanel-linux-$arch" .
done
ls -la dist/FreeNodePanel-linux-*
echo "构建完成：dist/FreeNodePanel-linux-amd64 / dist/FreeNodePanel-linux-arm64"
