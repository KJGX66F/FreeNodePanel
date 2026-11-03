//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func applyHidden(cmd *exec.Cmd) {
	// CREATE_NO_WINDOW：子进程（后台服务）不创建任何控制台窗口
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
		HideWindow:    true,
	}
}

// openBrowser 用系统默认浏览器打开面板页
func openBrowser(url string) {
	exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

var (
	user32DLL      = syscall.NewLazyDLL("user32.dll")
	procMessageBox = user32DLL.NewProc("MessageBoxW")
)

// notifyUser 无窗口模式下唯一的提示方式：系统消息框（仅异常时用）
func notifyUser(title, text string) {
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), 0x40) // MB_ICONINFORMATION
}
