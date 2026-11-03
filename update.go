package main

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// releaseVersion 本构建对应的发布版本，与 GitHub Release 标签保持一致
const releaseVersion = "v1.2.0"

// releasesPage 发布页；releasesLatest 会重定向到最新标签页，
// 从 Location 解析标签即可，不依赖 api.github.com（国内常不可达）
const releasesPage = "https://github.com/KJGX66F/FreeNodePanel/releases"
const releasesLatest = releasesPage + "/latest"

var (
	updMu     sync.Mutex
	updLatest string // 查到的、比当前版更新的最新版标签；无更新时为空
)

// parseVer 把 v1.2.3 解析成 [1 2 3]；解析失败返回 nil
func parseVer(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// verNewer a 是否比 b 新（按数值逐段比较；解析失败一律不算新）
func verNewer(a, b string) bool {
	va, vb := parseVer(a), parseVer(b)
	if va == nil || vb == nil {
		return false
	}
	for i := 0; i < len(va) || i < len(vb); i++ {
		var x, y int
		if i < len(va) {
			x = va[i]
		}
		if i < len(vb) {
			y = vb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// checkUpdateOnce 查一次最新发布版：出网链路与拉源保持一致——
// 用户在面板里配置的代理优先，其次直连，最后环境代理兜底。
// 任何失败都静默（没有横幅即代表没查到或已是最新）。
func checkUpdateOnce() {
	proxies := []string{userProxy(), ""}
	if envP := os.Getenv("HTTPS_PROXY"); envP != "" {
		proxies = append(proxies, envP)
	}
	for _, px := range proxies {
		c := httpClientVia(px, 6*time.Second)
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		resp, err := c.Get(releasesLatest)
		if err != nil {
			continue
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		i := strings.LastIndex(loc, "/tag/")
		if i < 0 {
			continue
		}
		tag := strings.TrimSpace(loc[i+len("/tag/"):])
		if tag == "" {
			continue
		}
		updMu.Lock()
		if verNewer(tag, releaseVersion) {
			updLatest = tag
		} else {
			updLatest = ""
		}
		updMu.Unlock()
		return
	}
}

// updateAvailable 返回可提示的新版本标签（无则空字符串）
func updateAvailable() string {
	updMu.Lock()
	defer updMu.Unlock()
	return updLatest
}

// startUpdateChecker 后台服务启动后延迟首查，之后每 24 小时查一次
func startUpdateChecker() {
	go func() {
		time.Sleep(30 * time.Second)
		for {
			checkUpdateOnce()
			time.Sleep(24 * time.Hour)
		}
	}()
}
