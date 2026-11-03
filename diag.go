package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var subTokenRe = regexp.MustCompile(`/sub/[A-Za-z0-9_-]{8,}`)

// buildDiagText 汇总一份纯文本诊断信息：版本、节点与各源状态、最近错误、日志尾部。
// 用户在面板点「复制诊断信息」后粘贴到 Issue/评论区，维护者不用再逐项追问。
// 注意：不包含订阅密钥和订阅地址。
func buildDiagText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "FreeNodePanel 诊断信息\n")
	fmt.Fprintf(&b, "时间：%s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "版本：%s（服务版本 %d）\n", releaseVersion, serviceVersion)
	fmt.Fprintf(&b, "系统：%s/%s\n", runtime.GOOS, runtime.GOARCH)
	if line := androidDNSDiagLine(); line != "" {
		fmt.Fprintf(&b, "%s\n", line)
	}
	if u := updateAvailable(); u != "" {
		fmt.Fprintf(&b, "可更新：%s\n", u)
	}

	total, counts := statusCounts()
	fmt.Fprintf(&b, "节点总数：%d", total)
	if total > 0 {
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
		}
		fmt.Fprintf(&b, "（%s）", strings.Join(parts, " · "))
	}
	b.WriteString("\n")

	stateMu.Lock()
	sr, er := slotsRefreshing, extRefreshing
	se := append([]string{}, slotsErrors...)
	extErrs := extErrors
	stateMu.Unlock()
	fmt.Fprintf(&b, "刷新状态：节点池 %s，外部源 %s\n", busyText(sr), busyText(er))
	if len(se) > 0 {
		fmt.Fprintf(&b, "节点池最近错误：%s\n", strings.Join(se, "；"))
	}

	b.WriteString("外部/自定义源：\n")
	for _, src := range allExtLikeSources() {
		c := readExtCache(src.Key)
		if c == nil {
			fmt.Fprintf(&b, "- %s：暂无缓存", src.Label)
		} else {
			fmt.Fprintf(&b, "- %s：共 %d → 留 %d · %s 更新", src.Label, c.Total, c.Keep, c.Fetched)
		}
		if e := extErrs[src.Key]; e != "" {
			fmt.Fprintf(&b, " · 最近失败：%s", e)
		}
		b.WriteString("\n")
	}
	if px := userProxy(); px != "" {
		fmt.Fprintf(&b, "面板代理设置：%s\n", px)
	} else {
		b.WriteString("面板代理设置：未设置（直连+镜像）\n")
	}

	b.WriteString("最近日志（尾部）：\n")
	b.WriteString(logTail(30))
	// 兜底脱敏：旧版本日志里可能记过完整订阅地址，统一把 /sub/<密钥> 打码，
	// 保证诊断信息粘到公开 Issue 也不会泄露密钥
	return subTokenRe.ReplaceAllString(b.String(), "/sub/****")
}

func busyText(x bool) string {
	if x {
		return "刷新中"
	}
	return "空闲"
}

// logTail 读 data/server.log 的最后 n 行；读不到时返回占位说明
func logTail(n int) string {
	p := filepath.Join(dataDir, "server.log")
	f, err := os.Open(p)
	if err != nil {
		return "（无日志文件）\n"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "（日志不可读）\n"
	}
	const maxRead = 256 << 10
	start := st.Size() - maxRead
	if start < 0 {
		start = 0
	}
	buf := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && len(buf) == 0 {
		return "（日志不可读）\n"
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}
