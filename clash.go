package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------- 分享链接 -> mihomo 代理（对齐原版 _clash_proxy） ----------
type clashProxy struct {
	Name        string         `yaml:"name"`
	Type        string         `yaml:"type"`
	Server      string         `yaml:"server"`
	Port        int            `yaml:"port"`
	UUID        string         `yaml:"uuid,omitempty"`
	AlterId     *int           `yaml:"alterId,omitempty"` // 指针：vmess 时哪怕是 0 也必须输出，mihomo 严格校验缺字段会整单拒绝
	Cipher      string         `yaml:"cipher,omitempty"`
	Password    string         `yaml:"password,omitempty"`
	UDP         bool           `yaml:"udp,omitempty"`
	TLS         bool           `yaml:"tls,omitempty"`
	Network     string         `yaml:"network,omitempty"`
	Servername  string         `yaml:"servername,omitempty"`
	SNI         string         `yaml:"sni,omitempty"`
	Flow        string         `yaml:"flow,omitempty"`
	Fingerprint string         `yaml:"client-fingerprint,omitempty"`
	SkipCert    bool           `yaml:"skip-cert-verify,omitempty"`
	RealityOpts map[string]any `yaml:"reality-opts,omitempty"`
	WSOpts      map[string]any `yaml:"ws-opts,omitempty"`
	HTTPOpts    map[string]any `yaml:"http-opts,omitempty"`
	AuthStr     string         `yaml:"auth-str,omitempty"`
	Protocol    string         `yaml:"protocol,omitempty"`
	ALPN        []string       `yaml:"alpn,omitempty"`
	Up          int            `yaml:"up,omitempty"`
	Down        int            `yaml:"down,omitempty"`
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func linkToClash(link, name string) *clashProxy {
	scheme := schemeOf(link)
	switch scheme {
	case "vmess":
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		b, err := b64DecodeLoose(body)
		if err != nil {
			return nil
		}
		var j map[string]any
		if json.Unmarshal(b, &j) != nil {
			return nil
		}
		aid := atoiSafe(strOf(j["aid"]))
		p := &clashProxy{Name: name, Type: "vmess", Server: strOf(j["add"]),
			Port: atoiSafe(strOf(j["port"])), UUID: strOf(j["id"]),
			AlterId: &aid, Cipher: "auto", UDP: true}
		if c := strOf(j["scy"]); c != "" {
			p.Cipher = c
		}
		if tl := j["tls"]; tl == "tls" || tl == true || tl == "1" {
			p.TLS = true
			if s := strOf(j["sni"]); s != "" {
				p.Servername = s
			}
		}
		net := strOf(j["net"])
		if net == "ws" || net == "h2" || net == "http" {
			p.Network = net
			opts := map[string]any{}
			if pa := strOf(j["path"]); pa != "" {
				opts["path"] = pa
			}
			if net == "ws" {
				if h := strOf(j["host"]); h != "" {
					opts["headers"] = map[string]any{"Host": h}
				}
				if len(opts) > 0 {
					p.WSOpts = opts
				}
			} else if net == "http" && len(opts) > 0 {
				p.HTTPOpts = opts
			}
		}
		return p
	case "vless":
		u, err := url.Parse(link)
		if err != nil {
			return nil
		}
		q := u.Query()
		net := q.Get("type")
		if net == "" {
			net = "tcp"
		}
		p := &clashProxy{Name: name, Type: "vless", Server: u.Hostname(), Port: atoiSafe(u.Port()),
			UDP: true, Network: net, Servername: q.Get("sni")}
		if u.User != nil {
			p.UUID = u.User.Username()
		}
		sec := q.Get("security")
		if sec == "tls" || sec == "reality" {
			p.TLS = true
		}
		if fp := q.Get("fp"); fp != "" {
			p.Fingerprint = fp
		}
		if fl := q.Get("flow"); fl != "" {
			p.Flow = fl
		}
		if sec == "reality" {
			p.RealityOpts = map[string]any{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
		}
		if net == "ws" && q.Get("path") != "" {
			p.WSOpts = map[string]any{"path": q.Get("path")}
		}
		if net == "http" && q.Get("path") != "" {
			p.HTTPOpts = map[string]any{"path": q.Get("path")}
		}
		return p
	case "trojan":
		u, err := url.Parse(link)
		if err != nil {
			return nil
		}
		q := u.Query()
		pw := ""
		if u.User != nil {
			pw, _ = url.PathUnescape(u.User.Username())
		}
		p := &clashProxy{Name: name, Type: "trojan", Server: u.Hostname(), Port: atoiSafe(u.Port()),
			Password: pw, UDP: true, SNI: q.Get("sni")}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			p.SkipCert = true
		}
		return p
	case "ss":
		scheme2, host, port, ok := parseLink(link)
		_ = scheme2
		if !ok {
			return nil
		}
		var cipher, pw string
		u, err := url.Parse(link)
		if err == nil && u.User != nil {
			raw := u.User.String()
			if dec, err := b64DecodeLoose(raw); err == nil && strings.Contains(string(dec), ":") {
				cipher, pw = string(dec[:strings.Index(string(dec), ":")]), string(dec[strings.Index(string(dec), ":")+1:])
			} else if strings.Contains(raw, ":") {
				cipher, pw = raw[:strings.Index(raw, ":")], raw[strings.Index(raw, ":")+1:]
				if d, err := url.PathUnescape(pw); err == nil {
					pw = d
				}
			}
		}
		if cipher == "" {
			body := link[len("ss://"):]
			body = strings.SplitN(body, "#", 2)[0]
			body = strings.SplitN(body, "?", 2)[0]
			if b, err := b64DecodeLoose(body); err == nil {
				s := string(b)
				if at := strings.LastIndex(s, "@"); at >= 0 {
					ui := s[:at]
					if ci := strings.Index(ui, ":"); ci >= 0 {
						cipher, pw = ui[:ci], ui[ci+1:]
					}
				}
			}
		}
		if cipher == "" {
			return nil
		}
		return &clashProxy{Name: name, Type: "ss", Server: host, Port: atoiSafe(port),
			Cipher: cipher, Password: pw, UDP: true}
	case "hysteria2":
		u, err := url.Parse(link)
		if err != nil {
			return nil
		}
		q := u.Query()
		auth := ""
		if u.User != nil {
			auth, _ = url.PathUnescape(u.User.String())
		}
		if auth == "" {
			auth = q.Get("auth")
		}
		p := &clashProxy{Name: name, Type: "hysteria2", Server: u.Hostname(), Port: atoiSafe(u.Port()),
			Password: auth, SNI: q.Get("sni"), UDP: true}
		if p.SNI == "" {
			p.SNI = q.Get("peer")
		}
		if q.Get("insecure") == "1" {
			p.SkipCert = true
		}
		if up := atoiSafe(q.Get("upmbps")); up > 0 {
			p.Up = up
			p.Down = atoiSafe(q.Get("downmbps"))
			if p.Down == 0 {
				p.Down = up
			}
		}
		return p
	case "hysteria":
		u, err := url.Parse(link)
		if err != nil {
			return nil
		}
		q := u.Query()
		p := &clashProxy{Name: name, Type: "hysteria", Server: u.Hostname(), Port: atoiSafe(u.Port()),
			Protocol: "udp", SNI: q.Get("peer"), AuthStr: q.Get("auth"), UDP: true}
		if p.SNI == "" {
			p.SNI = q.Get("sni")
		}
		alpn := q.Get("alpn")
		if alpn == "" {
			alpn = "h3"
		}
		p.ALPN = []string{alpn}
		if q.Get("insecure") == "1" {
			p.SkipCert = true
		}
		mbps := func(v string) int {
			m := regexp.MustCompile(`\d+`).FindString(v)
			return atoiSafe(m)
		}
		// mihomo 严格校验要求 hysteria 必须带 up/down，链接里没写就给保守默认值
		p.Up = mbps(q.Get("upmbps"))
		if p.Up == 0 {
			p.Up = 10
		}
		p.Down = mbps(q.Get("downmbps"))
		if p.Down == 0 {
			p.Down = 50
		}
		return p
	}
	return nil
}

type clashGroup struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Proxies   []string `yaml:"proxies"`
	URL       string   `yaml:"url,omitempty"`
	Interval  int      `yaml:"interval,omitempty"`
	Tolerance int      `yaml:"tolerance,omitempty"`
	Lazy      bool     `yaml:"lazy,omitempty"`
	MaxFails  int      `yaml:"max-fails,omitempty"`
}

type clashConfig struct {
	Proxies     []*clashProxy `yaml:"proxies"`
	ProxyGroups []clashGroup  `yaml:"proxy-groups"`
	Rules       []string      `yaml:"rules"`
}

func buildClashYAML(nodes []*Node) string {
	var proxies []*clashProxy
	var names []string
	taken := map[string]bool{}
	for _, n := range nodes {
		base := n.Name
		name := base
		for i := 2; taken[name]; i++ {
			name = base + " " + strconv.Itoa(i)
		}
		p := linkToClash(n.Link, name)
		if p == nil || p.Server == "" || p.Port == 0 {
			continue
		}
		taken[name] = true
		proxies = append(proxies, p)
		names = append(names, name)
	}
	if len(proxies) == 0 {
		return "proxies: []\n"
	}
	cfg := clashConfig{
		Proxies: proxies,
		ProxyGroups: []clashGroup{
			{Name: "🚀 节点选择", Type: "select", Proxies: append([]string{"♻️ 自动选择"}, names...)},
			{Name: "♻️ 自动选择", Type: "url-test", Proxies: names,
				URL: "http://www.gstatic.com/generate_204", Interval: 120, Tolerance: 100, Lazy: true, MaxFails: 3},
		},
		// 私有/本地地址必须直连：否则经内核更新本地订阅（如 127.0.0.1:8765）时
		// 请求会被送到远程节点，节点连不到用户本机而返回 502；局域网设备同理。
		Rules: []string{
			"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
			"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
			"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
			"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
			"IP-CIDR,::1/128,DIRECT,no-resolve",
			"DOMAIN-SUFFIX,local,DIRECT",
			"MATCH,🚀 节点选择",
		},
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "proxies: []\n"
	}
	return string(out)
}
