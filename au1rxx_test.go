package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// Au1rxx 解析器样例：覆盖实测中出现的每种协议与关键字段形态，
// 外加不支持协议、带插件/混淆的条目与残缺条目（都应被跳过并计数）
const au1rxxFixture = `
proxies:
  - name: vmess-tcp-tls
    type: vmess
    server: 203.0.113.10
    port: 443
    uuid: "11111111-2222-3333-4444-555555555555"
    alterId: 0
    cipher: auto
    network: tcp
    tls: true
    servername: example.com
  - name: vmess-ws
    type: vmess
    server: 203.0.113.11
    port: 8443
    uuid: "11111111-2222-3333-4444-555555555556"
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /ws-path
      headers:
        Host: cdn.example.com
  - name: vless-reality
    type: vless
    server: 203.0.113.20
    port: 443
    uuid: "22222222-3333-4444-5555-666666666666"
    network: tcp
    tls: true
    servername: itunes.apple.com
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    reality-opts:
      public-key: PUBKEY123
      short-id: ab12
  - name: vless-reality-ws-noise
    type: vless
    server: 203.0.113.21
    port: 443
    uuid: "22222222-3333-4444-5555-666666666667"
    network: ws
    tls: true
    servername: example.com
    reality-opts:
      public-key: PUBKEY456
      short-id: cd34
  - name: vless-ws-tls
    type: vless
    server: 203.0.113.22
    port: 443
    uuid: "22222222-3333-4444-5555-666666666668"
    network: ws
    tls: true
    servername: sni.example.com
    ws-opts:
      path: /vless-ws
      headers:
        Host: host.example.com
  - name: trojan-one
    type: trojan
    server: 203.0.113.30
    port: 443
    password: <redacted>
    sni: trojan.example.com
    skip-cert-verify: true
  - name: ss-plain
    type: ss
    server: 203.0.113.40
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: sspw2
  - name: ss-with-plugin
    type: ss
    server: 203.0.113.41
    port: 8388
    cipher: aes-256-gcm
    password: sspw
    plugin: obfs
    plugin-opts:
      mode: http
  - name: hy2-one
    type: hysteria2
    server: 203.0.113.60
    port: 443
    password: hy2pw
    sni: bing.com
    skip-cert-verify: true
  - name: hy2-obfs
    type: hysteria2
    server: 203.0.113.61
    port: 443
    password: hy2pw2
    obfs: salamander
    obfs-password: obfspw
  - name: hy1-one
    type: hysteria
    server: 203.0.113.50
    port: 443
    auth-str: hy1auth
    sni: hy1.example.com
    skip-cert-verify: true
    up: 10 Mbps
    down: 50 Mbps
  - name: tuic-one
    type: tuic
    server: 203.0.113.70
    port: 443
    uuid: "33333333-4444-5555-6666-777777777777"
    password: tuicpw
  - name: wg-one
    type: wireguard
    server: 203.0.113.71
    port: 51820
    private-key: PRIVKEY
    public-key: PUBKEY
  - name: vless-no-uuid
    type: vless
    server: 203.0.113.80
    port: 443
  - name: trojan-no-server
    type: trojan
    port: 443
    password: xx
`

func parseFixture(t *testing.T) ([]string, *clashYAMLStats) {
	t.Helper()
	links, st, err := parseClashYAMLLinks(au1rxxFixture)
	if err != nil {
		t.Fatalf("解析样例失败：%v", err)
	}
	return links, st
}

func findLink(t *testing.T, links []string, substr string) string {
	t.Helper()
	for _, l := range links {
		if strings.Contains(l, substr) {
			return l
		}
	}
	t.Fatalf("未找到包含 %q 的链接，全部链接：%v", substr, links)
	return ""
}

func queryOf(t *testing.T, link string) url.Values {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("链接无法解析：%s（%v）", link, err)
	}
	return u.Query()
}

// 总量口径：15 条里 9 条转换、2 条残缺、4 类不支持各 1 条
func TestAu1rxx_Counts(t *testing.T) {
	links, st := parseFixture(t)
	if st.Total != 15 {
		t.Errorf("Total=%d，期望 15", st.Total)
	}
	if st.Converted != 9 || len(links) != 9 {
		t.Errorf("Converted=%d len(links)=%d，期望 9", st.Converted, len(links))
	}
	if st.Broken != 2 {
		t.Errorf("Broken=%d，期望 2（缺 uuid、缺 server）", st.Broken)
	}
	for _, k := range []string{"tuic", "wireguard", "ss-plugin", "hysteria2-obfs"} {
		if st.Unsupported[k] != 1 {
			t.Errorf("Unsupported[%q]=%d，期望 1（全部：%v）", k, st.Unsupported[k], st.Unsupported)
		}
	}
}

// 每条转换出的链接都必须能被既有管线（parseLink/nodeFromLink）与
// Clash 输出（linkToClash）接受，否则并入管线后会无声丢失
func TestAu1rxx_LinksUsableByPipeline(t *testing.T) {
	links, _ := parseFixture(t)
	for _, l := range links {
		if _, _, _, ok := parseLink(l); !ok {
			t.Errorf("parseLink 拒绝转换结果：%s", l)
		}
		n := nodeFromLink(l, "")
		if n == nil {
			t.Errorf("nodeFromLink 拒绝转换结果：%s", l)
			continue
		}
		if p := linkToClash(l, "校验"); p == nil || p.Server == "" || p.Port == 0 {
			t.Errorf("linkToClash 无法处理转换结果：%s", l)
		}
	}
}

// vmess：alterId 保留为 0、tls/sni 进 JSON；ws 条目的 path/Host 不能丢
func TestAu1rxx_VMessFields(t *testing.T) {
	links, _ := parseFixture(t)
	decode := func(link string) map[string]any {
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		b, err := b64DecodeLoose(body)
		if err != nil {
			t.Fatalf("vmess 链接 body 不是合法 base64：%v", err)
		}
		var j map[string]any
		if err := json.Unmarshal(b, &j); err != nil {
			t.Fatalf("vmess 链接 body 不是合法 JSON：%v", err)
		}
		return j
	}
	j := decode(findLink(t, links, "vmess://"))
	// 第一条 vmess 是 tcp+tls 的（fixture 顺序），逐条找更稳妥：按 add 区分
	for _, l := range links {
		if !strings.HasPrefix(l, "vmess://") {
			continue
		}
		m := decode(l)
		switch strOf(m["add"]) {
		case "203.0.113.10":
			if strOf(m["aid"]) != "0" || strOf(m["tls"]) != "tls" || strOf(m["sni"]) != "example.com" {
				t.Errorf("vmess tcp 条目字段不对：%v", m)
			}
			if strOf(m["ps"]) != "vmess-tcp-tls" || strOf(m["scy"]) != "auto" {
				t.Errorf("vmess tcp 条目名称/加密不对：%v", m)
			}
		case "203.0.113.11":
			if strOf(m["net"]) != "ws" || strOf(m["path"]) != "/ws-path" || strOf(m["host"]) != "cdn.example.com" {
				t.Errorf("vmess ws 条目字段不对：%v", m)
			}
		}
	}
	_ = j
}

// vless：reality 的 pbk/sid/flow/fp 要齐；标了 ws 的 reality 必须归一到 tcp；
// 普通 ws+tls 的 path/Host 要进链接
func TestAu1rxx_VLessFields(t *testing.T) {
	links, _ := parseFixture(t)
	reality := findLink(t, links, "203.0.113.20")
	q := queryOf(t, reality)
	if q.Get("security") != "reality" || q.Get("pbk") != "PUBKEY123" || q.Get("sid") != "ab12" ||
		q.Get("flow") != "xtls-rprx-vision" || q.Get("fp") != "chrome" || q.Get("sni") != "itunes.apple.com" {
		t.Errorf("vless reality 链接参数不对：%s", reality)
	}
	noise := findLink(t, links, "203.0.113.21")
	q = queryOf(t, noise)
	if q.Get("security") != "reality" || q.Get("type") != "tcp" {
		t.Errorf("reality+ws 条目应归一为 tcp：%s", noise)
	}
	ws := findLink(t, links, "203.0.113.22")
	q = queryOf(t, ws)
	if q.Get("security") != "tls" || q.Get("type") != "ws" || q.Get("path") != "/vless-ws" || q.Get("host") != "host.example.com" {
		t.Errorf("vless ws 链接参数不对：%s", ws)
	}
}

// trojan/ss/hysteria2/hysteria 的关键字段
func TestAu1rxx_OtherProtocols(t *testing.T) {
	links, _ := parseFixture(t)

	tr := findLink(t, links, "trojan://")
	if q := queryOf(t, tr); q.Get("sni") != "trojan.example.com" || q.Get("allowInsecure") != "1" {
		t.Errorf("trojan 链接参数不对：%s", tr)
	}

	// 不能用 "ss://" 做子串查找："vmess://" 里也含这段，按服务器地址定位
	ss := findLink(t, links, "203.0.113.40")
	u, err := url.Parse(ss)
	if err != nil || u.User == nil {
		t.Fatalf("ss 链接结构不对：%s", ss)
	}
	dec, err := b64DecodeLoose(u.User.String())
	if err != nil || string(dec) != "chacha20-ietf-poly1305:sspw2" {
		t.Errorf("ss 凭据解码不对：%q（err=%v）", dec, err)
	}

	hy2 := findLink(t, links, "hysteria2://")
	if q := queryOf(t, hy2); q.Get("sni") != "bing.com" || q.Get("insecure") != "1" {
		t.Errorf("hysteria2 链接参数不对：%s", hy2)
	}

	hy1 := findLink(t, links, "hysteria://")
	if q := queryOf(t, hy1); q.Get("auth") != "hy1auth" || q.Get("peer") != "hy1.example.com" ||
		q.Get("upmbps") != "10" || q.Get("downmbps") != "50" {
		t.Errorf("hysteria 链接参数不对：%s", hy1)
	}
}

// 垃圾输入：整体解析失败要返回错误，让源状态能如实报错而不是静默 0 条
func TestAu1rxx_BadYAML(t *testing.T) {
	if _, _, err := parseClashYAMLLinks("proxies: [unclosed"); err == nil {
		t.Error("残缺 YAML 应返回错误")
	}
	if _, _, err := parseClashYAMLLinks("proxies:\n  - name: x\n    type: tuic\n    server: 1.2.3.4\n    port: 443\n"); err == nil {
		t.Error("全部条目都无法转换时应返回错误")
	}
}
