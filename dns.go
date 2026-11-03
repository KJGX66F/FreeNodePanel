package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// ---------- 安卓 DNS 兜底 ----------
//
// 背景：GOOS=android + CGO_ENABLED=0 的纯 Go 解析器读不到安卓的系统 DNS 配置
// （安卓没有 /etc/resolv.conf），会退回用 [::1]:53 / 127.0.0.1:53 当 DNS 服务器，
// 那里没人监听，所有域名解析直接 connection refused——拉源与测活全灭，
// 就是 v0.1.0 原型真机上「节点总数 0、全部源解析失败」的根因。
//
// 修法：仅在安卓运行模式下，把 net.DefaultResolver 换成一个自定义解析器，
// 它的 Dial 忽略 Go 递过来的坏地址，改拨真实可用的 DNS 服务器（UDP/TCP 53）：
// 优先用壳 App 从系统拿到的 DNS（环境变量 FNP_DNS 传入），拿不到就用公共兜底。
// 按调用计数轮换起始服务器：某台不可达时，后续查询会从别的服务器开始，
// 配合单次 Dial 内按顺序逐台尝试，一两台坏掉不至于全灭。
// 拉取与测活的代码都没有自设 Resolver（走默认 Transport / DefaultResolver），
// 所以装这一处即可全覆盖；桌面版不进这个分支，行为零变化。

var fallbackDNSServers = []string{"223.5.5.5", "119.29.29.29", "8.8.8.8"}

// dnsPort 内部可注入：生产恒为 53，单元测试把它指向本地假 DNS 服务器的端口。
var dnsPort = "53"

var (
	androidDNSActive  bool
	androidDNSSource  string // "shell" = 壳传入 / "fallback" = 兜底列表
	androidDNSServers []string
	dnsDialSeq        atomic.Uint64
)

// androidMode 表示当前是否跑在安卓壳里：编译目标是 android，或壳通过
// FNP_DATA_DIR 拉起（后者让 Linux 冒烟测试也能走同一条安卓代码路径）。
func androidMode() bool {
	return runtime.GOOS == "android" || os.Getenv("FNP_DATA_DIR") != ""
}

// parseDNSServers 解析 FNP_DNS：逗号分隔，逐个校验为合法 IP，坏的丢弃；
// 带 %zone 后缀的（如 fe80::1%wlan0）去掉后缀再校验。
func parseDNSServers(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if i := strings.Index(p, "%"); i >= 0 {
			p = p[:i]
		}
		if p != "" && net.ParseIP(p) != nil {
			out = append(out, p)
		}
	}
	return out
}

// dnsDialFunc 返回 Resolver.Dial 的实现：按轮换顺序逐台拨 servers 的 dnsPort
// 端口，第一台连上就用它。Resolver 递进来的 addr 参数（坏掉的 [::1]:53 之类）
// 一律忽略——那正是要绕开的东西。单独成函数是为了让单元测试能直接测它。
func dnsDialFunc(servers []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	list := append([]string{}, servers...)
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		proto := "udp"
		if strings.HasPrefix(network, "tcp") {
			proto = "tcp"
		}
		n := len(list)
		start := int(dnsDialSeq.Add(1)-1) % n
		var lastErr error
		for i := 0; i < n; i++ {
			d := net.Dialer{Timeout: 3 * time.Second}
			conn, err := d.DialContext(ctx, proto, net.JoinHostPort(list[(start+i)%n], dnsPort))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("DNS 服务器全部拨不通: %w", lastErr)
	}
}

// newRotatingResolver 造一个 PreferGo 解析器（强制走 Go 解析逻辑 + 上面的 Dial）。
func newRotatingResolver(servers []string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: dnsDialFunc(servers)}
}

// installAndroidDNS 在安卓模式下装上自定义解析器；其它平台直接返回、不碰任何东西。
// 必须在任何拉取/测活之前调用（serveMain 早期）。
func installAndroidDNS() {
	if !androidMode() {
		return
	}
	servers := parseDNSServers(os.Getenv("FNP_DNS"))
	if len(servers) > 0 {
		androidDNSSource = "shell"
	} else {
		servers = append([]string{}, fallbackDNSServers...)
		androidDNSSource = "fallback"
	}
	androidDNSServers = servers
	net.DefaultResolver = newRotatingResolver(servers)
	androidDNSActive = true
	logf("安卓模式：已启用自定义 DNS 解析（来源 %s，服务器 %s）", androidDNSSource, strings.Join(servers, ", "))
}

// androidDNSDiagLine 诊断信息用的一行 DNS 状态；非安卓模式返回空串（诊断里就不出现）。
func androidDNSDiagLine() string {
	if !androidDNSActive {
		return ""
	}
	if androidDNSSource == "shell" {
		return fmt.Sprintf("安卓DNS：壳传入 %d 个（%s）", len(androidDNSServers), strings.Join(androidDNSServers, ", "))
	}
	return fmt.Sprintf("安卓DNS：兜底（%s）", strings.Join(androidDNSServers, ", "))
}
