package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ---------- 自定义源：用户在面板里自己添加的订阅 / 节点列表地址 ----------
// 与内置外部源共用同一套下载、提取、测活、缓存逻辑（缓存文件 ext_cu_<id>.json），
// 每次全量刷新时一起更新；汇总时按「每个自定义源独立保留上限」并入订阅，
// 不和内置源抢全局 120 条 TCP 名额。

type customSource struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Added string `json:"added"`
}

var customMu sync.Mutex

func customFile() string { return filepath.Join(dataDir, "custom_sources.json") }

func loadCustomSources() []customSource {
	b, err := os.ReadFile(customFile())
	if err != nil {
		return nil
	}
	var list []customSource
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	return list
}

func saveCustomSources(list []customSource) {
	b, _ := json.Marshal(list)
	tmp := customFile() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, customFile())
	}
}

func (c customSource) key() string { return "cu_" + c.ID }

func (c customSource) label() string {
	if strings.TrimSpace(c.Name) != "" {
		return c.Name
	}
	if u, err := url.Parse(c.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return "自定义源"
}

// allExtLikeSources 内置外部源 + 自定义源，统一给刷新流程用
func allExtLikeSources() []extSource {
	out := append([]extSource{}, extSources...)
	for _, cs := range loadCustomSources() {
		out = append(out, extSource{Key: cs.key(), Label: cs.label(), URL: cs.URL})
	}
	return out
}

// customNodes 读取各自定义源的缓存，每个源独立套用保留上限后汇总
func customNodes() []*Node {
	type tcpItem struct {
		n  *Node
		ms int
	}
	var out []*Node
	for _, cs := range loadCustomSources() {
		c := readExtCache(cs.key())
		if c == nil {
			continue
		}
		var tcp []tcpItem
		var hy1, hy2 []*Node
		seen := map[string]bool{}
		for _, en := range c.Nodes {
			n := nodeFromLink(en.URL, en.Name)
			if n == nil {
				continue
			}
			n.Source = cs.label()
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
		sort.Slice(tcp, func(i, j int) bool { return tcp[i].ms < tcp[j].ms })
		for i, t := range tcp {
			if i >= extKeepTCP {
				break
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
	}
	return out
}
