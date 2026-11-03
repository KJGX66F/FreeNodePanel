//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

func applyHidden(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
}

// openBrowser 非 Windows（本地测试用）：尝试 xdg-open / open，失败忽略
func openBrowser(url string) {
	for _, c := range []string{"xdg-open", "open"} {
		if err := exec.Command(c, url).Start(); err == nil {
			return
		}
	}
}

// notifyUser 非 Windows 下退化为打印（Windows 版是系统消息框）
func notifyUser(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}
