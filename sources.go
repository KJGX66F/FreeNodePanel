package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// ---------- 全局路径与状态 ----------
var (
	dataDir  string
	cacheDir string
	logMu    sync.Mutex
)

func logf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, args...) + "\n"
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Print(line)
	if dataDir != "" {
		f, err := os.OpenFile(filepath.Join(dataDir, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			f.WriteString(line)
			f.Close()
		}
	}
}

func initDirs() error {
	// 安卓壳 App 通过 FNP_DATA_DIR 直接指定数据目录（App 的 files 目录）：
	// 安卓上可执行文件位于只读的 lib 目录，旁边放不了 data/，必须走这个覆盖。
	// 桌面版不设这个环境变量，行为与原来完全一致。
	if d := os.Getenv("FNP_DATA_DIR"); d != "" {
		dataDir = d
		cacheDir = filepath.Join(dataDir, "cache")
		return os.MkdirAll(cacheDir, 0o755)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dataDir = filepath.Join(filepath.Dir(self), "data")
	cacheDir = filepath.Join(dataDir, "cache")
	return os.MkdirAll(cacheDir, 0o755)
}

// ---------- 用户代理设置（data/proxy.json，可选） ----------
func userProxy() string {
	b, err := os.ReadFile(filepath.Join(dataDir, "proxy.json"))
	if err != nil {
		return ""
	}
	var j map[string]any
	if json.Unmarshal(b, &j) == nil {
		return strings.TrimSpace(strOf(j["proxy"]))
	}
	return ""
}

func setUserProxy(p string) {
	if p == "" {
		os.Remove(filepath.Join(dataDir, "proxy.json"))
		return
	}
	b, _ := json.Marshal(map[string]string{"proxy": p})
	os.WriteFile(filepath.Join(dataDir, "proxy.json"), b, 0o644)
}

// ---------- 出网：直连优先，失败按链路兜底 ----------
func httpClientVia(proxy string, timeout time.Duration) *http.Client {
	tr := &http.Transport{}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	} else {
		tr.Proxy = nil // 明确直连，不读系统/环境代理（与原版行为一致）
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

func fetchOnce(client *http.Client, u string, timeout time.Duration) (string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 ChromeGoPanel")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return "", fmt.Errorf("空响应")
	}
	return string(b), nil
}

// fetchChain 依次尝试一组地址（同一种出网方式）；返回正文
func fetchChain(urls []string, timeout time.Duration) (string, error) {
	proxies := []string{}
	if up := userProxy(); up != "" {
		proxies = append(proxies, up) // 用户明确填了代理就优先用它（原版策略）
	}
	proxies = append(proxies, "") // 直连
	if envP := os.Getenv("HTTPS_PROXY"); envP != "" {
		proxies = append(proxies, envP) // 有系统环境代理时最后兜底一次（家里一般没有）
	}
	var lastErr error
	for _, px := range proxies {
		c := httpClientVia(px, timeout)
		for _, u := range urls {
			txt, err := fetchOnce(c, u, timeout)
			if err == nil {
				return txt, nil
			}
			lastErr = err
			time.Sleep(300 * time.Millisecond)
		}
	}
	return "", lastErr
}

// ---------- ChromeGo 槽位 ----------
type toolDef struct {
	Label, Remote, File string
	Slots               int
}

var tools = []struct {
	Key string
	Def toolDef
}{
	{"xray", toolDef{"Xray", "xray", "config.json", 4}},
	{"clash.meta", toolDef{"Clash.Meta", "clash.meta2", "config.yaml", 6}},
	{"hysteria", toolDef{"Hysteria v1", "hysteria", "config.json", 4}},
	{"hysteria2", toolDef{"Hysteria2", "hysteria2", "config.json", 4}},
}

const gitlabTpl = "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/%s/%d/%s"
const mirrorTpl = "https://www.67867867.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/%s/%d/%s"

func slotCacheFile(key string, def toolDef, slot int) string {
	ext := ".json"
	if strings.HasSuffix(def.File, ".yaml") {
		ext = ".yaml"
	}
	return filepath.Join(cacheDir, fmt.Sprintf("%s_ip%d%s", key, slot, ext))
}

func fetchSlot(def toolDef, slot int) (string, error) {
	urls := []string{
		fmt.Sprintf(gitlabTpl, def.Remote, slot, def.File),
		fmt.Sprintf(mirrorTpl, def.Remote, slot, def.File),
	}
	return fetchChain(urls, 25*time.Second)
}

// ---------- 节点 ----------
type Node struct {
	Protocol string // 主协议：vless/vmess/trojan/ss/hysteria/hysteria2
	Server   string
	Port     string
	Link     string
	Name     string
	V2N      bool   // 能否进 v2rayN 订阅（hysteria v1 不能）
	Source   string // 展示用来源标签（槽位或外部源）
	Ms       int    // 测活延迟（毫秒）；0 = 未测活/未知（槽位与 Hysteria 系）
}

func nodeFromLink(link, name string) *Node {
	scheme, host, port, ok := parseLink(link)
	if !ok {
		return nil
	}
	if name == "" {
		name = linkName(link)
	}
	return &Node{Protocol: scheme, Server: host, Port: port, Link: link, Name: name, V2N: scheme != "hysteria"}
}

func dedupeKey(n *Node) string {
	return n.Protocol + "|" + strings.ToLower(n.Server) + "|" + n.Port + "|" + linkCredential(n.Link)
}

// ---------- 槽位配置解析（对齐原版 parse_config_text） ----------
func parseSlotConfig(text, label string) []*Node {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		var data map[string]any
		if err := json.Unmarshal([]byte(text), &data); err != nil {
			return nil
		}
		return parseSlotJSON(data, label)
	}
	// YAML（Clash.Meta 槽位）
	var ydoc map[string]any
	if err := yaml.Unmarshal([]byte(text), &ydoc); err != nil {
		return nil
	}
	return parseClashDoc(ydoc, label)
}

func parseSlotJSON(data map[string]any, label string) []*Node {
	if _, ok := data["auth_str"]; ok {
		if _, ok2 := data["server"]; ok2 {
			if n := parseHy1JSON(data, label); n != nil {
				return []*Node{n}
			}
			return nil
		}
	}
	if _, ok := data["auth"]; ok {
		if _, ok2 := data["bandwidth"]; ok2 {
			if _, ok3 := data["server"]; ok3 {
				if n := parseHy2JSON(data, label); n != nil {
					return []*Node{n}
				}
				return nil
			}
		}
	}
	if obs, ok := data["outbounds"].([]any); ok && len(obs) > 0 {
		if ob, ok := obs[0].(map[string]any); ok && strOf(ob["protocol"]) == "vless" {
			if n := parseXray(ob, label); n != nil {
				return []*Node{n}
			}
		}
	}
	if proxies, ok := data["proxies"].([]any); ok && len(proxies) > 0 {
		var out []*Node
		for i, pv := range proxies {
			if pm, ok := pv.(map[string]any); ok {
				if n := parseClashProxyMap(pm, fmt.Sprintf("%s#%d", label, i+1)); n != nil {
					out = append(out, n)
				}
			}
		}
		return out
	}
	return nil
}

func parseClashDoc(doc map[string]any, label string) []*Node {
	proxies, ok := doc["proxies"].([]any)
	if !ok || len(proxies) == 0 {
		return nil
	}
	var out []*Node
	for i, pv := range proxies {
		if pm, ok := pv.(map[string]any); ok {
			lbl := label
			if len(proxies) > 1 {
				lbl = fmt.Sprintf("%s#%d", label, i+1)
			}
			if n := parseClashProxyMap(pm, lbl); n != nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func getMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func getList(m map[string]any, key string) []any {
	if v, ok := m[key].([]any); ok {
		return v
	}
	return nil
}

func parseXray(ob map[string]any, label string) *Node {
	settings := getMap(ob, "settings")
	vnext := getList(settings, "vnext")
	if len(vnext) == 0 {
		return nil
	}
	v := vnext[0].(map[string]any)
	users := getList(v, "users")
	if len(users) == 0 {
		return nil
	}
	u := users[0].(map[string]any)
	ss := getMap(ob, "streamSettings")
	security := strOf(ss["security"])
	if security == "" {
		security = "tls"
	}
	network := strOf(ss["network"])
	if network == "" {
		network = "tcp"
	}
	var rs, xs map[string]any
	if security == "reality" {
		rs = getMap(ss, "realitySettings")
	}
	xs = getMap(ss, "xhttpSettings")
	sni := strOf(rs["serverName"])
	if sni == "" {
		sni = strOf(getMap(ss, "tlsSettings")["serverName"])
	}
	fp := strOf(rs["fingerprint"])
	if fp == "" && security == "reality" {
		fp = "chrome"
	}
	enc := strOf(u["encryption"])
	if enc == "" {
		enc = "none"
	}
	qs := buildQS([]kv{
		{"encryption", enc}, {"security", security}, {"type", network},
		{"sni", sni}, {"fp", fp}, {"pbk", strOf(rs["publicKey"])},
		{"sid", strOf(rs["shortId"])}, {"path", strOf(xs["path"])}, {"mode", strOf(xs["mode"])},
	})
	addr, port := strOf(v["address"]), strOf(v["port"])
	link := fmt.Sprintf("vless://%s@%s?%s#%s", strOf(u["id"]), hostPort(addr, port), qs, url.QueryEscape(label))
	return &Node{Protocol: "vless", Server: addr, Port: port, Link: link, Name: label, V2N: true}
}

func parseHy1JSON(d map[string]any, label string) *Node {
	server := strOf(d["server"])
	if server == "" {
		server = strOf(d["server_addr"]) + ":" + strOf(d["server_port"])
	}
	host, port, ok := splitHostPortLoose(server)
	if !ok {
		return nil
	}
	auth := strOf(d["auth_str"])
	if auth == "" {
		auth = strOf(d["auth"])
	}
	sni := strOf(d["server_name"])
	if sni == "" {
		sni = strOf(d["peer"])
	}
	insecure := "0"
	if boolOf(d["insecure"]) {
		insecure = "1"
	}
	alpn := strOf(d["alpn"])
	if alpn == "" {
		alpn = "h3"
	}
	qs := buildQS([]kv{
		{"auth", auth}, {"peer", sni}, {"insecure", insecure},
		{"upmbps", strOf(d["up_mbps"])}, {"downmbps", strOf(d["down_mbps"])}, {"alpn", alpn},
	})
	link := fmt.Sprintf("hysteria://%s?%s#%s", hostPort(host, port), qs, url.QueryEscape(label))
	return &Node{Protocol: "hysteria", Server: host, Port: port, Link: link, Name: label, V2N: false}
}

func parseHy2JSON(d map[string]any, label string) *Node {
	host, port, ok := splitHostPortLoose(strOf(d["server"]))
	if !ok {
		return nil
	}
	tls := getMap(d, "tls")
	insecure := "0"
	if boolOf(tls["insecure"]) {
		insecure = "1"
	}
	return hy2Node(strOf(d["auth"]), host, port, strOf(tls["sni"]), insecure, "", "", label)
}

func hy2Node(auth, host, port, sni, insecure, up, down, label string) *Node {
	qs := buildQS([]kv{{"sni", sni}, {"insecure", insecure}, {"upmbps", up}, {"downmbps", down}})
	link := fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.QueryEscape(auth), hostPort(host, port), qs, url.QueryEscape(label))
	return &Node{Protocol: "hysteria2", Server: host, Port: port, Link: link, Name: label, V2N: true}
}

func parseClashProxyMap(p map[string]any, label string) *Node {
	t := strOf(p["type"])
	server, port := strOf(p["server"]), strOf(p["port"])
	if server == "" || port == "" {
		return nil
	}
	insecure := "0"
	if boolOf(p["skip-cert-verify"]) {
		insecure = "1"
	}
	switch t {
	case "hysteria2":
		return hy2Node(strOf(p["password"]), server, port, strOf(p["sni"]), insecure,
			digits(strOf(p["up"])), digits(strOf(p["down"])), label)
	case "hysteria":
		auth := strOf(p["auth-str"])
		if auth == "" {
			auth = strOf(p["auth_str"])
		}
		if auth == "" {
			auth = strOf(p["auth"])
		}
		alpn := "h3"
		if al, ok := p["alpn"].([]any); ok && len(al) > 0 {
			var parts []string
			for _, a := range al {
				parts = append(parts, strOf(a))
			}
			alpn = strings.Join(parts, ",")
		}
		d := map[string]any{
			"server": server + ":" + port, "auth_str": auth, "server_name": strOf(p["sni"]),
			"insecure": insecure == "1", "up_mbps": digits(strOf(p["up"])), "down_mbps": digits(strOf(p["down"])),
			"alpn": alpn,
		}
		return parseHy1JSON(d, label)
	case "vless":
		reality := getMap(p, "reality-opts")
		net := strOf(p["network"])
		if net == "" {
			net = "tcp"
		}
		sec := strOf(p["security"])
		if sec == "" {
			sec = "tls"
		}
		path := strOf(p["path"])
		if net == "http" {
			if ho, ok := p["http-opts"].(map[string]any); ok {
				if pl, ok := ho["path"].([]any); ok && len(pl) > 0 {
					path = strOf(pl[0])
				}
			}
		}
		enc := strOf(p["encryption"])
		if enc == "" {
			enc = "none"
		}
		qs := buildQS([]kv{
			{"encryption", enc}, {"security", sec}, {"sni", strOf(p["servername"])},
			{"fp", strOf(p["client-fingerprint"])}, {"pbk", strOf(reality["public-key"])},
			{"sid", strOf(reality["short-id"])}, {"type", net}, {"path", path},
		})
		link := fmt.Sprintf("vless://%s@%s?%s#%s", strOf(p["uuid"]), hostPort(server, port), qs, url.QueryEscape(label))
		return &Node{Protocol: "vless", Server: server, Port: port, Link: link, Name: label, V2N: true}
	case "trojan":
		qs := buildQS([]kv{{"sni", strOf(p["sni"])}, {"allowInsecure", insecure}})
		link := fmt.Sprintf("trojan://%s@%s?%s#%s", url.QueryEscape(strOf(p["password"])), hostPort(server, port), qs, url.QueryEscape(label))
		return &Node{Protocol: "trojan", Server: server, Port: port, Link: link, Name: label, V2N: true}
	case "ss":
		ui := b64URLEncodeNoPad([]byte(strOf(p["cipher"]) + ":" + strOf(p["password"])))
		link := fmt.Sprintf("ss://%s@%s#%s", ui, hostPort(server, port), url.QueryEscape(label))
		return &Node{Protocol: "ss", Server: server, Port: port, Link: link, Name: label, V2N: true}
	}
	return nil
}
