package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNodeFromLink(t *testing.T) {
	n := nodeFromLink("vless://22222222-3333-4444-5555-666666666666@203.0.113.20:8443?security=tls&type=tcp#my-name", "")
	if n == nil {
		t.Fatal("vless 链接解析失败")
	}
	if n.Protocol != "vless" || n.Server != "203.0.113.20" || n.Port != "8443" {
		t.Errorf("解析结果不对：%+v", n)
	}
	if n.Name != "my-name" {
		t.Errorf("名称应取链接 fragment，得到 %q", n.Name)
	}
	if !n.V2N {
		t.Error("vless 应可用于 v2rayN")
	}
	hy := nodeFromLink("hysteria://203.0.113.50:443?auth=abc#hy", "")
	if hy == nil || hy.V2N {
		t.Error("hysteria v1 应被标记为仅 Clash 可用")
	}
	if nodeFromLink("not-a-link", "") != nil {
		t.Error("非法链接应返回 nil")
	}
}

func TestDedupeKey(t *testing.T) {
	a := nodeFromLink("vless://u@203.0.113.20:8443#name-a", "")
	b := nodeFromLink("vless://u@203.0.113.20:8443#name-b", "")
	if a == nil || b == nil {
		t.Fatal("解析失败")
	}
	if dedupeKey(a) != dedupeKey(b) {
		t.Error("同服务器同凭证、仅名称不同的节点应判重")
	}
	c := nodeFromLink("vless://u@203.0.113.20:9999#name-a", "")
	if dedupeKey(a) == dedupeKey(c) {
		t.Error("端口不同的节点不应判重")
	}
}

func TestSortByLatency(t *testing.T) {
	mk := func(name string, ms int) *Node { return &Node{Name: name, Ms: ms} }
	in := []*Node{mk("slot", 0), mk("slow", 300), mk("fast", 50), mk("hy2", 0), mk("mid", 120)}
	out := sortByLatency(in)
	got := []string{out[0].Name, out[1].Name, out[2].Name, out[3].Name, out[4].Name}
	want := []string{"fast", "mid", "slow", "slot", "hy2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("排序结果 %v，期望 %v", got, want)
		}
	}
	if in[0].Name != "slot" {
		t.Error("sortByLatency 不应修改原切片")
	}
}

func TestVerNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.2.0", "v1.1.0", true},
		{"v1.1.0", "v1.2.0", false},
		{"v1.1.0", "v1.1.0", false},
		{"v1.10.0", "v1.9.0", true}, // 数值比较，不是字符串比较
		{"v2", "v1.9.9", true},
		{"bad", "v1.0.0", false},
		{"v1.0.1", "v1.0.0", true},
	}
	for _, c := range cases {
		if got := verNewer(c.a, c.b); got != c.want {
			t.Errorf("verNewer(%q, %q) = %v，期望 %v", c.a, c.b, got, c.want)
		}
	}
}

func TestExtractLinks(t *testing.T) {
	text := "看看这个 vless://u@203.0.113.20:8443#x 和 trojan://p@203.0.113.30:443#y 不错"
	got := extractLinks(text)
	if len(got) != 2 {
		t.Fatalf("应提取 2 条链接，得到 %d：%v", len(got), got)
	}
	// base64 订阅正文应被解码后提取
	inner := "vless://u@203.0.113.20:8443#x\nss://abc@203.0.113.40:8388#y"
	enc := base64.StdEncoding.EncodeToString([]byte(inner))
	got = extractLinks(enc)
	if len(got) != 2 {
		t.Fatalf("base64 正文应提取 2 条链接，得到 %d", len(got))
	}
	if !strings.HasPrefix(got[0], "vless://") {
		t.Errorf("提取结果异常：%v", got)
	}
}
