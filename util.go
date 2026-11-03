package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func wrapHost(host string) string {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

func hostPort(host, port string) string { return wrapHost(host) + ":" + port }

// qs 按给定顺序拼查询串，丢掉空值（与原版 _qs 行为一致）
type kv struct{ k, v string }

func buildQS(pairs []kv) string {
	var parts []string
	for _, p := range pairs {
		if p.v == "" || p.v == "0" {
			continue
		}
		parts = append(parts, url.QueryEscape(p.k)+"="+url.QueryEscape(p.v))
	}
	return strings.Join(parts, "&")
}

func digits(s string) string {
	m := regexp.MustCompile(`\d+`).FindString(s)
	return m
}

func b64DecodeLoose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func b64EncodeStr(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func b64URLEncodeNoPad(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func splitHostPortLoose(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, true
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", false
	}
	host := strings.Trim(s[:i], "[]")
	port := s[i+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", false
	}
	return host, port, true
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func schemeOf(link string) string {
	i := strings.Index(link, "://")
	if i < 0 {
		return ""
	}
	s := strings.ToLower(link[:i])
	switch s {
	case "hy2":
		return "hysteria2"
	case "hy":
		return "hysteria"
	}
	return s
}

// parseLink 解析分享链接 -> (主协议, host, port, ok)，用于去重与测活
func parseLink(link string) (string, string, string, bool) {
	scheme := schemeOf(link)
	if scheme == "" {
		return "", "", "", false
	}
	if scheme == "vmess" {
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		b, err := b64DecodeLoose(body)
		if err != nil {
			return "", "", "", false
		}
		var j map[string]any
		if err := jsonUnmarshal(b, &j); err != nil {
			return "", "", "", false
		}
		add := strOf(j["add"])
		port := strOf(j["port"])
		if add == "" || port == "" {
			return "", "", "", false
		}
		return scheme, add, port, true
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", "", "", false
	}
	host, port := u.Hostname(), u.Port()
	if host != "" && port != "" {
		return scheme, host, port, true
	}
	if scheme == "ss" {
		// 老格式 ss://base64(cipher:pw@host:port)
		body := link[len("ss://"):]
		body = strings.SplitN(body, "#", 2)[0]
		body = strings.SplitN(body, "?", 2)[0]
		if b, err := b64DecodeLoose(body); err == nil {
			s := string(b)
			if at := strings.LastIndex(s, "@"); at >= 0 {
				if h, p, ok := splitHostPortLoose(s[at+1:]); ok {
					return scheme, h, p, true
				}
			}
		}
	}
	return "", "", "", false
}

// linkCredential 取链接里的凭据部分，用于同服务器不同凭据的去重区分
func linkCredential(link string) string {
	scheme := schemeOf(link)
	if scheme == "vmess" {
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		if b, err := b64DecodeLoose(body); err == nil {
			var j map[string]any
			if jsonUnmarshal(b, &j) == nil {
				return strOf(j["id"])
			}
		}
		return ""
	}
	if u, err := url.Parse(link); err == nil && u.User != nil {
		return u.User.String()
	}
	return ""
}

func linkName(link string) string {
	if schemeOf(link) == "vmess" {
		body := strings.SplitN(link[len("vmess://"):], "#", 2)[0]
		if b, err := b64DecodeLoose(body); err == nil {
			var j map[string]any
			if jsonUnmarshal(b, &j) == nil && strOf(j["ps"]) != "" {
				return strOf(j["ps"])
			}
		}
	}
	if u, err := url.Parse(link); err == nil && u.Fragment != "" {
		if n, err := url.PathUnescape(u.Fragment); err == nil {
			return n
		}
		return u.Fragment
	}
	return "节点"
}

func strOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func boolOf(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	case float64:
		return t != 0
	}
	return false
}
