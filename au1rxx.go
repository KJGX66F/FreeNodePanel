package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------- Au1rxx 节点池：Clash YAML 订阅解析 ----------
// Au1rxx/free-vpn-subscriptions 只发布 Clash 格式的 YAML（output/clash.yaml 是
// 全量汇总文件），不像其它外部源那样是链接列表。所以这个源的抓取结果要先把
// proxies 条目逐条翻译成项目内部通用的分享链接，再并入既有的提取→测活→保留
// 管线（见 ext.go refreshExtSource 中 src.YAML 分支），后面的环节与其它源无异。
//
// 翻译口径：
//   - 覆盖 vmess / vless / trojan / ss / hysteria / hysteria2 六种内部模型能
//     完整表达的协议；其余协议（tuic、wireguard 等）跳过并计数，不硬塞。
//   - 内部链接口径表达不了的传输选项同样跳过并计数：ss 的 plugin、
//     hysteria2 的 obfs——硬留下来只会生成连不上的死节点。
//   - server/port 为空、缺 uuid/password 等残缺条目跳过并计数。
//   - network 归一化：raw 是新版内核对 tcp 的改名，按 tcp 处理；无法识别的
//     脏值（上游生成器偶尔会把备注糊进 network 字段）也按 tcp 处理。
//     reality 只在 tcp 上成立：带 reality-opts 的条目若标了 ws/grpc 等网络，
//     强制按 tcp 处理（这类条目基本都带 xtls-rprx-vision，本就是 tcp 专用）。

type clashYAMLStats struct {
	Total       int            // YAML 里 proxies 总条数
	Converted   int            // 成功翻译成链接的条数
	Broken      int            // 残缺条目（缺服务器/端口/凭据）跳过数
	Unsupported map[string]int // 跳过的协议/选项 → 数量，如 "tuic"、"ss-plugin"
}

func (s *clashYAMLStats) skip(kind string) {
	if s.Unsupported == nil {
		s.Unsupported = map[string]int{}
	}
	s.Unsupported[kind]++
}

func (s *clashYAMLStats) summary() string {
	if len(s.Unsupported) == 0 {
		return fmt.Sprintf("共 %d 条 → 转换 %d 条（残缺跳过 %d）", s.Total, s.Converted, s.Broken)
	}
	parts := make([]string, 0, len(s.Unsupported))
	for k, v := range s.Unsupported {
		parts = append(parts, fmt.Sprintf("%s×%d", k, v))
	}
	return fmt.Sprintf("共 %d 条 → 转换 %d 条（残缺跳过 %d；不支持跳过：%s）",
		s.Total, s.Converted, s.Broken, strings.Join(parts, "、"))
}

// parseClashYAMLLinks 把一份 Clash YAML 文本翻译成分享链接列表
func parseClashYAMLLinks(text string) ([]string, *clashYAMLStats, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, nil, fmt.Errorf("YAML 解析失败：%v", err)
	}
	st := &clashYAMLStats{Total: len(doc.Proxies)}
	var links []string
	for _, pm := range doc.Proxies {
		link, why := clashProxyToLink(pm)
		if link == "" {
			if why == "broken" {
				st.Broken++
			} else {
				st.skip(why)
			}
			continue
		}
		st.Converted++
		links = append(links, link)
	}
	if st.Total > 0 && st.Converted == 0 {
		return nil, st, fmt.Errorf("YAML 共 %d 条节点但一条都没能转换", st.Total)
	}
	return links, st, nil
}

// normClashNetwork 归一化 Clash 的 network 字段到内部链接口径
func normClashNetwork(net string) string {
	switch strings.ToLower(strings.TrimSpace(net)) {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "grpc", "http", "h2", "httpupgrade":
		return strings.ToLower(strings.TrimSpace(net))
	default:
		return "tcp"
	}
}

// wsOptsOf 取 Clash ws-opts 的 path 与 Host 头（没有就是空）
func wsOptsOf(p map[string]any) (path, host string) {
	wo := getMap(p, "ws-opts")
	path = strOf(wo["path"])
	if hdrs, ok := wo["headers"].(map[string]any); ok {
		host = strOf(hdrs["Host"])
		if host == "" {
			host = strOf(hdrs["host"])
		}
	}
	return path, host
}

// clashProxyToLink 单条 Clash 代理 → 分享链接；返回 ("", 原因) 表示跳过，
// 原因 "broken" = 条目残缺，其它值 = 不支持的协议/选项名（用于统计）
func clashProxyToLink(p map[string]any) (string, string) {
	server, port := strOf(p["server"]), strOf(p["port"])
	if server == "" || port == "" || port == "0" {
		return "", "broken"
	}
	name := strOf(p["name"])
	if name == "" {
		name = "节点"
	}
	hp := hostPort(server, port)
	insecure := "0"
	if boolOf(p["skip-cert-verify"]) {
		insecure = "1"
	}
	sni := strOf(p["servername"])
	if sni == "" {
		sni = strOf(p["sni"])
	}
	net := normClashNetwork(strOf(p["network"]))

	switch strOf(p["type"]) {
	case "vmess":
		uuid := strOf(p["uuid"])
		if uuid == "" {
			return "", "broken"
		}
		cipher := strOf(p["cipher"])
		if cipher == "" {
			cipher = "auto"
		}
		j := map[string]any{
			"v": "2", "ps": name, "add": server, "port": port, "id": uuid,
			"aid": strOf(p["alterId"]), "scy": cipher, "net": net, "type": "none",
		}
		if net == "ws" || net == "httpupgrade" {
			path, host := wsOptsOf(p)
			j["path"], j["host"] = path, host
		}
		if boolOf(p["tls"]) {
			j["tls"] = "tls"
			if sni != "" {
				j["sni"] = sni
			}
		}
		b, err := json.Marshal(j)
		if err != nil {
			return "", "broken"
		}
		return "vmess://" + b64EncodeStr(string(b)), ""

	case "vless":
		uuid := strOf(p["uuid"])
		if uuid == "" {
			return "", "broken"
		}
		reality := getMap(p, "reality-opts")
		pbk := strOf(reality["public-key"])
		sec := "none"
		switch {
		case pbk != "":
			sec = "reality"
			net = "tcp" // reality 只在 tcp 上成立，标了别的网络按生成噪声处理
		case boolOf(p["tls"]):
			sec = "tls"
		}
		enc := strOf(p["encryption"])
		if enc == "" {
			enc = "none"
		}
		pairs := []kv{
			{"encryption", enc}, {"security", sec}, {"sni", sni},
			{"fp", strOf(p["client-fingerprint"])}, {"pbk", pbk},
			{"sid", strOf(reality["short-id"])}, {"flow", strOf(p["flow"])},
			{"type", net},
		}
		if net == "ws" || net == "httpupgrade" {
			path, host := wsOptsOf(p)
			pairs = append(pairs, kv{"host", host}, kv{"path", path})
		}
		if net == "grpc" {
			pairs = append(pairs, kv{"serviceName", strOf(getMap(p, "grpc-opts")["grpc-service-name"])})
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, hp, buildQS(pairs), url.QueryEscape(name)), ""

	case "trojan":
		pw := strOf(p["password"])
		if pw == "" {
			return "", "broken"
		}
		pairs := []kv{{"sni", strOf(p["sni"])}, {"allowInsecure", insecure}}
		if pairs[0].v == "" {
			pairs[0].v = strOf(p["servername"])
		}
		if net == "ws" || net == "httpupgrade" {
			path, host := wsOptsOf(p)
			pairs = append(pairs, kv{"type", net}, kv{"host", host}, kv{"path", path})
		}
		return fmt.Sprintf("trojan://%s@%s?%s#%s", url.QueryEscape(pw), hp, buildQS(pairs), url.QueryEscape(name)), ""

	case "ss":
		cipher, pw := strOf(p["cipher"]), strOf(p["password"])
		if cipher == "" || pw == "" {
			return "", "broken"
		}
		if pl := strOf(p["plugin"]); pl != "" {
			return "", "ss-plugin" // 内部口径表达不了插件传输，留下来也是死节点
		}
		ui := b64URLEncodeNoPad([]byte(cipher + ":" + pw))
		return fmt.Sprintf("ss://%s@%s#%s", ui, hp, url.QueryEscape(name)), ""

	case "hysteria2":
		pw := strOf(p["password"])
		if pw == "" {
			return "", "broken"
		}
		if ob := strOf(p["obfs"]); ob != "" {
			return "", "hysteria2-obfs" // 同上，内部口径没有 obfs 字段
		}
		qs := buildQS([]kv{
			{"sni", strOf(p["sni"])}, {"insecure", insecure},
			{"upmbps", digits(strOf(p["up"]))}, {"downmbps", digits(strOf(p["down"]))},
		})
		return fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.QueryEscape(pw), hp, qs, url.QueryEscape(name)), ""

	case "hysteria":
		auth := strOf(p["auth-str"])
		if auth == "" {
			auth = strOf(p["auth_str"])
		}
		if auth == "" {
			auth = strOf(p["auth"])
		}
		if auth == "" {
			return "", "broken"
		}
		alpn := "h3"
		if al, ok := p["alpn"].([]any); ok && len(al) > 0 {
			var parts []string
			for _, a := range al {
				parts = append(parts, strOf(a))
			}
			alpn = strings.Join(parts, ",")
		}
		// 复用槽位 JSON 的 hysteria v1 组装逻辑，保证链接口径全项目一致
		n := parseHy1JSON(map[string]any{
			"server": hp, "auth_str": auth, "server_name": strOf(p["sni"]),
			"insecure": insecure == "1",
			"up_mbps":  digits(strOf(p["up"])), "down_mbps": digits(strOf(p["down"])),
			"alpn": alpn,
		}, name)
		if n == nil {
			return "", "broken"
		}
		return n.Link, ""

	default:
		t := strOf(p["type"])
		if t == "" {
			return "", "broken"
		}
		return "", t
	}
}
