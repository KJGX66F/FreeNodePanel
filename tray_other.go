//go:build !windows

package main

import (
	"net/http"
	"os"
)

// serveWithTray 非 Windows 版（本地测试用）：没有系统托盘，直接监听
func serveWithTray(srv *http.Server) error {
	return srv.ListenAndServe()
}

// exitService 非 Windows 版：直接结束进程
func exitService() {
	os.Exit(0)
}
