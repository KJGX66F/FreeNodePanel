package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 一组可解析的示例链接，覆盖全部协议
func sampleNodes(t *testing.T) []*Node {
	t.Helper()
	vmessJSON := `{"v":"2","ps":"vmess-test","add":"203.0.113.10","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"tcp","tls":"tls","sni":"example.com"}`
	links := []string{
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)),
		"vless://22222222-3333-4444-5555-666666666666@203.0.113.20:8443?security=tls&type=tcp#vless-test",
		"trojan://pass123@203.0.113.30:443?sni=example.com#trojan-test",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pwd123")) + "@203.0.113.40:8388#ss-test",
		"hysteria://203.0.113.50:443?auth=abc&peer=example.com&insecure=1#hy-test",
		"hysteria2://pass@203.0.113.60:443?sni=example.com#hy2-test",
	}
	var out []*Node
	for _, l := range links {
		n := nodeFromLink(l, "")
		if n == nil {
			t.Fatalf("示例链接解析失败：%s", l)
		}
		out = append(out, n)
	}
	return out
}

// 回归：VMess 的 alterId 为 0 时也必须显式输出，否则 mihomo 严格校验会整份拒绝
func TestClashYAML_VMessAlterIdAlwaysEmitted(t *testing.T) {
	y := buildClashYAML(sampleNodes(t))
	if !strings.Contains(y, "alterId: 0") {
		t.Errorf("生成的 YAML 缺少 alterId: 0，mihomo 会报 has unset fields:\n%s", y)
	}
}

// 回归：Hysteria v1 链接没写 upmbps/downmbps 时必须补默认值，mihomo 要求 up/down 必填
func TestClashYAML_HysteriaUpDownDefaults(t *testing.T) {
	y := buildClashYAML(sampleNodes(t))
	if !strings.Contains(y, "up: 10") || !strings.Contains(y, "down: 50") {
		t.Errorf("Hysteria 节点缺少 up/down 默认值:\n%s", y)
	}
}

// 本机/局域网直连规则必须排在 MATCH 之前，否则经内核更新本地订阅会被绕到远程节点
func TestClashYAML_LANRulesBeforeMatch(t *testing.T) {
	y := buildClashYAML(sampleNodes(t))
	lan := strings.Index(y, "IP-CIDR,127.0.0.0/8,DIRECT")
	match := strings.Index(y, "MATCH,")
	if lan < 0 {
		t.Fatalf("缺少 127.0.0.0/8 直连规则:\n%s", y)
	}
	if match < 0 || lan > match {
		t.Errorf("直连规则必须在 MATCH 之前（lan=%d, match=%d）", lan, match)
	}
}

// 全部示例节点都应成功转换，且产物是合法 YAML
func TestClashYAML_AllSampleNodesConvert(t *testing.T) {
	nodes := sampleNodes(t)
	y := buildClashYAML(nodes)
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(y), &doc); err != nil {
		t.Fatalf("生成的 YAML 无法解析：%v", err)
	}
	if len(doc.Proxies) != len(nodes) {
		t.Errorf("转换后 proxies=%d，期望 %d:\n%s", len(doc.Proxies), len(nodes), y)
	}
}
