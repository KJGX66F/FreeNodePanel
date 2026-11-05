package main

// 一键节点提取工具 · 无窗口面板版
// 单个 EXE 两种模式：
//   无参数（用户双击）= 无窗口启动器：整个过程不显示任何窗口。它负责把后台服务拉起来、
//     触发一次全量自动刷新，然后自动用浏览器打开「操作面板」网页，之后自己退出。
//   --serve           = 后台服务：没有任何窗口，常驻提供订阅（v2rayN / Clash 同一地址自动分流），
//     启动时自动刷新全部源，之后每 3 小时再刷一遍。所有操作都在浏览器面板里完成。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const base = "http://127.0.0.1:8765"

type toolsInfo struct {
	App             string `json:"app"`
	Version         int    `json:"version"`
	SubURL          string `json:"sub_url"`
	SlotsRefreshing bool   `json:"slots_refreshing"`
	ExtRefreshing   bool   `json:"ext_refreshing"`
	Total           int    `json:"total"`
}

func getTools() (*toolsInfo, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(base + "/api/tools")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t toolsInfo
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

func postAPI(path string) {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Post(base+path, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func startServeHidden() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "--serve")
	cmd.Dir = filepath.Dir(self)
	applyHidden(cmd)
	return cmd.Start()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--serve" {
		os.Exit(serveMain())
	}
	// 安卓壳 App 拉起时只给环境变量、不带参数：设了 FNP_DATA_DIR 就直接进服务模式
	// （没有桌面启动器，也不需要它——界面由 App 的 WebView 承载）。
	if os.Getenv("FNP_DATA_DIR") != "" {
		os.Exit(serveMain())
	}
	launcherMain()
}

// launcherMain 全程无窗口：异常情况用系统弹窗提示，正常情况只打开浏览器面板。
func launcherMain() {
	tools, err := getTools()
	running := err == nil
	if running && tools.App != appMark {
		notifyUser("端口被旧版面板占用",
			"检测到旧版面板（有黑色窗口的那个）还在运行，占用着 8765 端口。\n\n请先关掉旧版面板的黑色窗口，再重新双击本程序。")
		return
	}
	if running && tools.Version < 17 {
		notifyUser("需要先停掉旧后台",
			"检测到上一个版本的后台服务还在运行。\n\n请先双击同目录的「停止后台.bat」停掉它，再把这个新 EXE 放到原来的文件夹里（覆盖旧的同名文件，这样原来的订阅地址不变），最后重新双击本程序。")
		return
	}
	if !running {
		if err := startServeHidden(); err != nil {
			notifyUser("启动失败", "后台服务启动失败："+err.Error())
			return
		}
		ok := false
		for i := 0; i < 120; i++ {
			if t, err := getTools(); err == nil && t.App == appMark && t.Version >= 17 {
				ok = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !ok {
			notifyUser("启动超时", "后台服务启动超时。\n\n详细日志在程序旁边的 data\\server.log，可以截图发给我看。")
			return
		}
	}
	// 每次打开都触发一次全量刷新（服务刚启动时它自己也会刷，重复触发会自动跳过）
	postAPI("/api/fetch_all")
	postAPI("/api/ext_refresh")
	// 打开操作面板：进度、节点列表、订阅地址都在这个页面里
	// FNP_NO_BROWSER=1 时跳过（安卓壳 App 等无桌面浏览器的环境用它兜底）
	if os.Getenv("FNP_NO_BROWSER") == "" {
		openBrowser(base + "/")
	}
}
