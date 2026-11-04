package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- 外部公共源（与原版 EXT_SOURCES 完全一致） ----------
// YAML=true 的源发布的是 Clash 格式订阅，抓到后先经 au1rxx.go 的解析器
// 翻译成分享链接，再走和其它源相同的提取/测活/保留管线。
type extSource struct {
	Key, Label, URL, Mirror, Relay string
	YAML                           bool
}

var extSources = []extSource{
	{"ermaozi", "ermaozi",
		"https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
		"https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/v2ray.txt",
		"https://wget.la/https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", false},
	{"cbusifab", "cbusifabcap",
		"https://raw.githubusercontent.com/cbusifabcap/daily_free_vpn/main/Z.txt",
		"https://cdn.jsdelivr.net/gh/cbusifabcap/daily_free_vpn@main/Z.txt",
		"https://wget.la/https://raw.githubusercontent.com/cbusifabcap/daily_free_vpn/main/Z.txt", false},
	{"leilao", "LeilaoMi真测",
		"https://raw.githubusercontent.com/LeilaoMi/AutoMergePublicNodes-Optimized/main/output/global.urls",
		"https://cdn.jsdelivr.net/gh/LeilaoMi/AutoMergePublicNodes-Optimized@main/output/global.urls",
		"https://wget.la/https://raw.githubusercontent.com/LeilaoMi/AutoMergePublicNodes-Optimized/main/output/global.urls", false},
	{"aliilapro", "ALIILAPRO",
		"https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
		"https://cdn.jsdelivr.net/gh/ALIILAPRO/v2rayNG-Config@main/sub.txt",
		"https://wget.la/https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt", false},
	{"au1rxx", "Au1rxx 节点池",
		"https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml",
		"https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/clash.yaml",
		"https://wget.la/https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml", true},
}

const (
	extKeepTCP  = 120
	extKeepHy1  = 20
	extKeepHy2  = 60
	extProbeMax = 800
)

var extSchemes = map[string]bool{
	"vmess": true, "vless": true, "trojan": true, "ss": true,
	"hysteria": true, "hysteria2": true,
}

// ---------- 状态 ----------
var (
	stateMu         sync.Mutex
	slotsRefreshing bool
	slotsErrors     []string
	extRefreshing   bool
	extErrors       = map[string]string{}
	extAttempt      = map[string]time.Time{}
)

func tryStartSlots() bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	if slotsRefreshing {
		return false
	}
	slotsRefreshing = true
	return true
}
func endSlots(errs []string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	slotsRefreshing = false
	slotsErrors = errs
}
func tryStartExt() bool {
	stateMu.Lock()
	defer stateMu.Unlock()
	if extRefreshing {
		return false
	}
	extRefreshing = true
	return true
}
func endExt() {
	stateMu.Lock()
	defer stateMu.Unlock()
	extRefreshing = false
}

// ---------- ChromeGo 槽位刷新 ----------
func refreshSlotsSync() (int, []string) {
	type job struct {
		key  string
		def  toolDef
		slot int
	}
	var jobs []job
	for _, t := range tools {
		for s := 1; s <= t.Def.Slots; s++ {
			jobs = append(jobs, job{t.Key, t.Def, s})
		}
	}
	errs := make([]string, len(jobs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, jb := range jobs {
		wg.Add(1)
		go func(i int, jb job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			text, err := fetchSlot(jb.def, jb.slot)
			if err != nil {
				errs[i] = fmt.Sprintf("%s 源%d", jb.def.Label, jb.slot)
				return
			}
			tmp := slotCacheFile(jb.key, jb.def, jb.slot) + ".tmp"
			if os.WriteFile(tmp, []byte(text), 0o644) == nil {
				os.Rename(tmp, slotCacheFile(jb.key, jb.def, jb.slot))
			}
		}(i, jb)
	}
	wg.Wait()
	var out []string
	for _, e := range errs {
		if e != "" {
			out = append(out, e)
		}
	}
	nodes, _ := aggregateNodes(false)
	return len(nodes), out
}

func slotNodes() []*Node {
	var out []*Node
	for _, t := range tools {
		for s := 1; s <= t.Def.Slots; s++ {
			b, err := os.ReadFile(slotCacheFile(t.Key, t.Def, s))
			if err != nil {
				continue
			}
			label := fmt.Sprintf("%s-源%d", t.Def.Label, s)
			for _, n := range parseSlotConfig(string(b), label) {
				if n.Source == "" {
					n.Source = label
				}
				out = append(out, n)
			}
		}
	}
	return out
}

// ---------- 外部源缓存结构 ----------
type extCacheNode struct {
	URL  string `json:"url"`
	Name string `json:"name"`
	Ms   *int   `json:"ms"`
}
type extCache struct {
	Fetched  string         `json:"fetched"`
	Source   string         `json:"source"`
	Total    int            `json:"total"`
	TCP      int            `json:"tcp"`
	TCPAlive int            `json:"tcp_alive"`
	Hy1      int            `json:"hy1"`
	Hy2      int            `json:"hy2"`
	Keep     int            `json:"keep"`
	Nodes    []extCacheNode `json:"nodes"`
}

func extCachePath(key string) string { return filepath.Join(cacheDir, "ext_"+key+".json") }

func readExtCache(key string) *extCache {
	b, err := os.ReadFile(extCachePath(key))
	if err != nil {
		return nil
	}
	var c extCache
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return &c
}

// ---------- 链接提取与测活 ----------
var linkRe = regexp.MustCompile(`(?i)(vless|vmess|trojan|hysteria2|hysteria|hy2|hy|ss)://[^\s"'<>]+`)

func extractLinks(text string) []string {
	if !strings.Contains(text[:min(len(text), 4000)], "://") {
		if b, err := b64DecodeLoose(strings.TrimSpace(text)); err == nil && strings.Contains(string(b), "://") {
			text = string(b)
		}
	}
	var out []string
	for _, m := range linkRe.FindAllString(text, -1) {
		out = append(out, strings.TrimRight(m, ")]},，。；;"))
	}
	return out
}

func linkTLSInfo(link string) (bool, string) {
	scheme := schemeOf(link)
	if scheme == "vmess" {
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		if b, err := b64DecodeLoose(body); err == nil {
			var j map[string]any
			if json.Unmarshal(b, &j) == nil {
				t := j["tls"]
				isTLS := t == "tls" || t == true || t == "1"
				sni := strOf(j["sni"])
				if sni == "" {
					sni = strOf(j["host"])
				}
				return isTLS, sni
			}
		}
		return false, ""
	}
	u, err := url.Parse(link)
	if err != nil {
		return false, ""
	}
	q := u.Query()
	if scheme == "trojan" {
		sni := q.Get("sni")
		if sni == "" {
			sni = u.Hostname()
		}
		return true, sni
	}
	sec := q.Get("security")
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	return sec == "tls" || sec == "reality", sni
}

func linkWSInfo(link string) (string, string, bool) {
	scheme := schemeOf(link)
	if scheme == "vmess" {
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		if b, err := b64DecodeLoose(body); err == nil {
			var j map[string]any
			if json.Unmarshal(b, &j) == nil {
				net := strOf(j["net"])
				if net == "ws" || net == "httpupgrade" {
					p := strOf(j["path"])
					if p == "" {
						p = "/"
					}
					return strOf(j["host"]), p, true
				}
			}
		}
		return "", "", false
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", "", false
	}
	q := u.Query()
	t := q.Get("type")
	if t == "" {
		t = "tcp"
	}
	if t == "ws" || t == "httpupgrade" {
		p := q.Get("path")
		if p == "" {
			p = "/"
		}
		return q.Get("host"), p, true
	}
	return "", "", false
}

// probeLink 真握手测活：TCP 连接 -> (TLS 握手) -> (ws 101 升级)，返回毫秒
func probeLink(link string) *int {
	_, host, port, ok := parseLink(link)
	if !ok {
		return nil
	}
	useTLS, sni := linkTLSInfo(link)
	wsHost, wsPath, isWS := linkWSInfo(link)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	for _, ip := range ips {
		ms := probeIP(ip.String(), port, host, useTLS, sni, isWS, wsHost, wsPath)
		if ms != nil {
			return ms
		}
	}
	return nil
}

func probeIP(ip, port, host string, useTLS bool, sni string, isWS bool, wsHost, wsPath string) *int {
	d := &net.Dialer{Timeout: 4 * time.Second}
	start := time.Now()
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var c net.Conn = conn
	if useTLS {
		name := sni
		if name == "" {
			name = host
		}
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: name})
		if err := tc.Handshake(); err != nil {
			return nil
		}
		c = tc
	}
	if isWS {
		h := wsHost
		if h == "" {
			h = sni
		}
		if h == "" {
			h = host
		}
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", wsPath, h)
		if _, err := c.Write([]byte(req)); err != nil {
			return nil
		}
		buf := make([]byte, 0, 256)
		tmp := make([]byte, 128)
		for !strings.Contains(string(buf), "\n") && len(buf) < 256 {
			n, err := c.Read(tmp)
			if n <= 0 || err != nil {
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		first := strings.SplitN(string(buf), "\n", 2)[0]
		if !strings.Contains(first, " 101") {
			return nil
		}
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1 // 钳到最小 1ms：0 专用于表示「未测活」，不能和测得的亚毫秒混淆
	}
	return &ms
}

// ---------- 外部源刷新 ----------
func refreshExtSource(src extSource) (*extCache, error) {
	var urls []string
	for _, u := range []string{src.URL, src.Mirror, src.Relay} {
		if strings.TrimSpace(u) != "" {
			urls = append(urls, u)
		}
	}
	text, err := fetchChain(urls, 45*time.Second)
	if err != nil {
		return nil, fmt.Errorf("直连和镜像都没拉下来：%v", err)
	}
	var links []string
	if src.YAML {
		// Clash YAML 源：先把 proxies 翻译成分享链接，后面的管线与其它源一致
		ls, st, perr := parseClashYAMLLinks(text)
		if perr != nil {
			return nil, perr
		}
		logf("外部源 %s：YAML %s", src.Label, st.summary())
		links = ls
	} else {
		links = extractLinks(text)
	}
	seen := map[string]bool{}
	var tcp, hy1, hy2 []string
	total := 0
	for _, l := range links {
		scheme, host, port, ok := parseLink(l)
		if !ok || !extSchemes[scheme] {
			continue
		}
		key := scheme + "|" + strings.ToLower(host) + "|" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		total++
		// 统一别名协议为标准写法
		if strings.HasPrefix(l, "hy2://") {
			l = "hysteria2://" + l[len("hy2://"):]
		} else if strings.HasPrefix(l, "hy://") {
			l = "hysteria://" + l[len("hy://"):]
		}
		switch scheme {
		case "hysteria2":
			hy2 = append(hy2, l)
		case "hysteria":
			hy1 = append(hy1, l)
		default:
			tcp = append(tcp, l)
		}
	}
	// vmess 排后面送测（原版策略）
	sort.SliceStable(tcp, func(i, j int) bool {
		return !strings.HasPrefix(tcp[i], "vmess://") && strings.HasPrefix(tcp[j], "vmess://")
	})
	probe := tcp
	if len(probe) > extProbeMax {
		probe = probe[:extProbeMax]
	}
	type res struct {
		url string
		ms  *int
	}
	results := make([]res, len(probe))
	sem := make(chan struct{}, 60)
	var wg sync.WaitGroup
	for i, l := range probe {
		wg.Add(1)
		go func(i int, l string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = res{l, probeLink(l)}
		}(i, l)
	}
	wg.Wait()
	type aliveT struct {
		url string
		ms  int
	}
	var alive []aliveT
	for _, r := range results {
		if r.ms != nil {
			alive = append(alive, aliveT{r.url, *r.ms})
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].ms < alive[j].ms })
	keepTCP := alive
	if len(keepTCP) > extKeepTCP {
		keepTCP = keepTCP[:extKeepTCP]
	}
	msOf := map[string]int{}
	var keep []extCacheNode
	for _, a := range keepTCP {
		msOf[a.url] = a.ms
		m := a.ms
		keep = append(keep, extCacheNode{URL: a.url, Name: linkName(a.url), Ms: &m})
	}
	hy1Keep := hy1
	if len(hy1Keep) > extKeepHy1 {
		hy1Keep = hy1Keep[:extKeepHy1]
	}
	hy2Keep := hy2
	if len(hy2Keep) > extKeepHy2 {
		hy2Keep = hy2Keep[:extKeepHy2]
	}
	for _, u := range hy1Keep {
		keep = append(keep, extCacheNode{URL: u, Name: linkName(u)})
	}
	for _, u := range hy2Keep {
		keep = append(keep, extCacheNode{URL: u, Name: linkName(u)})
	}
	c := &extCache{
		Fetched:  time.Now().Format("2006-01-02 15:04"),
		Total:    total,
		TCP:      len(tcp),
		TCPAlive: len(keepTCP),
		Hy1:      len(hy1Keep),
		Hy2:      len(hy2Keep),
		Keep:     len(keep),
		Nodes:    keep,
	}
	b, _ := json.Marshal(c)
	tmp := extCachePath(src.Key) + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, extCachePath(src.Key))
	}
	return c, nil
}

func refreshExtAllSync() {
	var wg sync.WaitGroup
	for _, src := range allExtLikeSources() {
		wg.Add(1)
		go func(src extSource) {
			defer wg.Done()
			stateMu.Lock()
			extAttempt[src.Key] = time.Now()
			stateMu.Unlock()
			_, err := refreshExtSource(src)
			stateMu.Lock()
			if err != nil {
				extErrors[src.Key] = err.Error()
				logf("外部源 %s 刷新失败：%v", src.Label, err)
			} else {
				delete(extErrors, src.Key)
			}
			stateMu.Unlock()
		}(src)
	}
	wg.Wait()
}

// ---------- 汇总 ----------
func extNodes() []*Node {
	type tcpItem struct {
		n  *Node
		ms int
	}
	var tcp []tcpItem
	var hy1, hy2 []*Node
	seen := map[string]bool{}
	for _, src := range extSources {
		c := readExtCache(src.Key)
		if c == nil {
			continue
		}
		for _, en := range c.Nodes {
			n := nodeFromLink(en.URL, en.Name)
			if n == nil {
				continue
			}
			n.Source = src.Label
			k := dedupeKey(n)
			if seen[k] {
				continue
			}
			seen[k] = true
			switch n.Protocol {
			case "hysteria2":
				hy2 = append(hy2, n)
			case "hysteria":
				hy1 = append(hy1, n)
			default:
				ms := 99999
				if en.Ms != nil {
					ms = *en.Ms
				}
				tcp = append(tcp, tcpItem{n, ms})
			}
		}
	}
	sort.Slice(tcp, func(i, j int) bool { return tcp[i].ms < tcp[j].ms })
	var out []*Node
	for i, t := range tcp {
		if i >= extKeepTCP {
			break
		}
		if t.ms < 99999 {
			t.n.Ms = t.ms
		}
		out = append(out, t.n)
	}
	for i, n := range hy1 {
		if i >= extKeepHy1 {
			break
		}
		out = append(out, n)
	}
	for i, n := range hy2 {
		if i >= extKeepHy2 {
			break
		}
		out = append(out, n)
	}
	return out
}

// sortByLatency 返回按测活延迟排序的副本：测过的节点按延迟从低到高排前面，
// 未测活的（槽位、Hysteria 系）保持原有相对顺序排后面。只用于订阅输出，
// 不影响面板明细的按源分组顺序。
func sortByLatency(nodes []*Node) []*Node {
	out := append([]*Node{}, nodes...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Ms, out[j].Ms
		if (a > 0) != (b > 0) {
			return a > 0
		}
		if a > 0 && b > 0 {
			return a < b
		}
		return false
	})
	return out
}

// aggregateNodes 全部节点去重汇总。v2nOnly=true 时剔除 hysteria v1
func aggregateNodes(v2nOnly bool) ([]*Node, map[string]bool) {
	seen := map[string]bool{}
	var out []*Node
	add := func(n *Node) {
		if n == nil {
			return
		}
		if v2nOnly && !n.V2N {
			return
		}
		k := dedupeKey(n)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, n)
	}
	for _, n := range slotNodes() {
		add(n)
	}
	for _, n := range extNodes() {
		add(n)
	}
	for _, n := range customNodes() {
		add(n)
	}
	return out, seen
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
