@echo off
rem 在 Windows 上一键构建：需要已安装 Go 1.23+
rem 产物： dist\免费公益节点面板.exe（GUI 子系统，双击无黑窗口）
setlocal
cd /d %~dp0
if not exist dist mkdir dist
set CGO_ENABLED=0
go build -trimpath -ldflags "-s -w -H windowsgui" -o "dist\免费公益节点面板.exe" .
if %errorlevel% neq 0 (
  echo 构建失败，请确认 Go 已正确安装并在 PATH 中。
  pause
  exit /b 1
)
echo 构建完成： dist\免费公益节点面板.exe
pause
