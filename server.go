package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const panelPort = 8765
const appMark = "freenodepanel"

// serviceVersion 服务自检版本：每次发布递增，启动器靠它识别并拒绝复用旧后台
const serviceVersion = 14

var (
	tokenMu  sync.RWMutex
	subToken string
)

func currentToken() string {
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	return subToken
}

func saveTokenFile(t string) {
	b, _ := json.Marshal(map[string]string{"token": t})
	os.WriteFile(filepath.Join(dataDir, "sub.json"), b, 0o644)
}

func loadToken() string {
	p := filepath.Join(dataDir, "sub.json")
	if b, err := os.ReadFile(p); err == nil {
		var j map[string]any
		if json.Unmarshal(b, &j) == nil && strOf(j["token"]) != "" {
			t := strOf(j["token"])
			tokenMu.Lock()
			subToken = t
			tokenMu.Unlock()
			return t
		}
	}
	t := randToken()
	tokenMu.Lock()
	subToken = t
	tokenMu.Unlock()
	saveTokenFile(t)
	return t
}

// resetToken 生成新密钥并落盘，旧订阅地址随即失效（面板上的「重置订阅密钥」按钮用）
func resetToken() string {
	t := randToken()
	tokenMu.Lock()
	subToken = t
	tokenMu.Unlock()
	saveTokenFile(t)
	return t
}

func subURL() string { return fmt.Sprintf("http://127.0.0.1:%d/sub/%s", panelPort, currentToken()) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(b)
}

func buildSubV2ray() string {
	nodes, _ := aggregateNodes(true)
	nodes = sortByLatency(nodes)
	var links []string
	for _, n := range nodes {
		links = append(links, n.Link)
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

func statusCounts() (int, map[string]int) {
	nodes, _ := aggregateNodes(true)
	counts := map[string]int{}
	for _, n := range nodes {
		counts[n.Protocol]++
	}
	return len(nodes), counts
}

func serveMain() int {
	if err := initDirs(); err != nil {
		fmt.Println("初始化数据目录失败：", err)
		return 1
	}
	loadToken()
	startUpdateChecker()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		total, counts := statusCounts()
		stateMu.Lock()
		sr, er := slotsRefreshing, extRefreshing
		stateMu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		html := statusHTML
		html = strings.ReplaceAll(html, "{{SUB}}", subURL())
		html = strings.ReplaceAll(html, "{{TOTAL}}", fmt.Sprint(total))
		html = strings.ReplaceAll(html, "{{VLESS}}", fmt.Sprint(counts["vless"]))
		html = strings.ReplaceAll(html, "{{VMESS}}", fmt.Sprint(counts["vmess"]))
		html = strings.ReplaceAll(html, "{{TROJAN}}", fmt.Sprint(counts["trojan"]))
		html = strings.ReplaceAll(html, "{{SS}}", fmt.Sprint(counts["ss"]))
		html = strings.ReplaceAll(html, "{{HY2}}", fmt.Sprint(counts["hysteria2"]))
		html = strings.ReplaceAll(html, "{{SR}}", fmt.Sprint(sr))
		html = strings.ReplaceAll(html, "{{ER}}", fmt.Sprint(er))
		w.Write([]byte(html))
	})

	mux.HandleFunc("/api/tools", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		sr, er := slotsRefreshing, extRefreshing
		stateMu.Unlock()
		total, _ := statusCounts()
		m := map[string]any{
			"app": appMark, "version": serviceVersion, "sub_url": subURL(),
			"slots_refreshing": sr, "ext_refreshing": er, "total": total,
			"release": releaseVersion,
		}
		if latest := updateAvailable(); latest != "" {
			m["update_available"] = latest
			m["release_url"] = releasesLatest
		}
		writeJSON(w, 200, m)
	})

	mux.HandleFunc("/api/diag", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"text": buildDiagText()})
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		total, counts := statusCounts()
		stateMu.Lock()
		sr, er := slotsRefreshing, extRefreshing
		se := slotsErrors
		stateMu.Unlock()
		writeJSON(w, 200, map[string]any{
			"app": appMark, "total": total, "counts": counts,
			"slots_refreshing": sr, "ext_refreshing": er, "slots_errors": se,
		})
	})

	mux.HandleFunc("/api/ext", func(w http.ResponseWriter, r *http.Request) {
		var items []map[string]any
		stateMu.Lock()
		er := extRefreshing
		errs := extErrors
		attempts := extAttempt
		stateMu.Unlock()
		for _, src := range extSources {
			it := map[string]any{"key": src.Key, "label": src.Label, "fetched": nil,
				"total": nil, "tcp": 0, "tcp_alive": 0, "hy1": 0, "hy2": 0, "keep": 0,
				"failed_at": nil, "error": nil}
			if c := readExtCache(src.Key); c != nil {
				it["fetched"] = c.Fetched
				it["total"] = c.Total
				it["tcp"] = c.TCP
				it["tcp_alive"] = c.TCPAlive
				it["hy1"] = c.Hy1
				it["hy2"] = c.Hy2
				it["keep"] = c.Keep
			}
			if e, ok := errs[src.Key]; ok {
				it["error"] = e
			}
			if t, ok := attempts[src.Key]; ok {
				it["failed_at"] = t.Format("15:04")
			}
			items = append(items, it)
		}
		for _, cs := range loadCustomSources() {
			it := map[string]any{"key": cs.key(), "label": cs.label(), "custom": true, "id": cs.ID, "url": cs.URL,
				"fetched": nil, "total": nil, "tcp": 0, "tcp_alive": 0, "hy1": 0, "hy2": 0, "keep": 0,
				"failed_at": nil, "error": nil}
			if c := readExtCache(cs.key()); c != nil {
				it["fetched"] = c.Fetched
				it["total"] = c.Total
				it["tcp"] = c.TCP
				it["tcp_alive"] = c.TCPAlive
				it["hy1"] = c.Hy1
				it["hy2"] = c.Hy2
				it["keep"] = c.Keep
			}
			if e, ok := errs[cs.key()]; ok {
				it["error"] = e
			}
			if t, ok := attempts[cs.key()]; ok {
				it["failed_at"] = t.Format("15:04")
			}
			items = append(items, it)
		}
		writeJSON(w, 200, map[string]any{"ext": items, "refreshing": er,
			"keep_tcp": extKeepTCP, "keep_hy1": extKeepHy1, "keep_hy2": extKeepHy2,
			"proxy_cfg": userProxy()})
	})

	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		nodes, _ := aggregateNodes(false)
		items := make([]map[string]any, 0, len(nodes))
		v2n := 0
		for _, n := range nodes {
			if n.V2N {
				v2n++
			}
			items = append(items, map[string]any{
				"name": n.Name, "protocol": n.Protocol, "server": n.Server,
				"port": n.Port, "link": n.Link, "v2n": n.V2N, "source": n.Source,
				"ms": n.Ms,
			})
		}
		writeJSON(w, 200, map[string]any{"total": len(nodes), "v2n_total": v2n, "nodes": items})
	})

	mux.HandleFunc("/api/fetch_all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		if !tryStartSlots() {
			writeJSON(w, 200, map[string]any{"ok": true, "hint": "已在刷新中"})
			return
		}
		// 后台刷新，面板轮询 /api/status 显示进度，页面不用等、也不用盯黑窗口
		go func() {
			_, errs := refreshSlotsSync()
			endSlots(errs)
		}()
		writeJSON(w, 200, map[string]any{"ok": true, "hint": "已开始后台刷新"})
	})

	mux.HandleFunc("/api/ext_refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		if !tryStartExt() {
			writeJSON(w, 200, map[string]any{"ok": true, "hint": "已在刷新中"})
			return
		}
		go func() {
			defer endExt()
			refreshExtAllSync()
		}()
		writeJSON(w, 200, map[string]any{"ok": true, "hint": "后台刷新中，TCP 节点要真握手测活，通常一分多钟"})
	})

	mux.HandleFunc("/api/custom_add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		name := strings.TrimSpace(strOf(body["name"]))
		u := strings.TrimSpace(strOf(body["url"]))
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			writeJSON(w, 200, map[string]any{"ok": false, "error": "地址要以 http:// 或 https:// 开头"})
			return
		}
		if len([]rune(name)) > 30 {
			name = string([]rune(name)[:30])
		}
		customMu.Lock()
		list := loadCustomSources()
		for _, cs := range list {
			if cs.URL == u {
				customMu.Unlock()
				writeJSON(w, 200, map[string]any{"ok": false, "error": "这个地址已经添加过了"})
				return
			}
		}
		if len(list) >= 20 {
			customMu.Unlock()
			writeJSON(w, 200, map[string]any{"ok": false, "error": "最多添加 20 个自定义源"})
			return
		}
		id := randToken()
		if len(id) > 10 {
			id = id[:10]
		}
		list = append(list, customSource{ID: id, Name: name, URL: u, Added: time.Now().Format("2006-01-02 15:04")})
		saveCustomSources(list)
		customMu.Unlock()
		// 立刻后台刷新一遍，新源马上就能出节点
		if tryStartExt() {
			go func() {
				defer endExt()
				refreshExtAllSync()
			}()
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hint": "已添加，正在后台拉取并测活，约 1-2 分钟后出节点"})
	})

	mux.HandleFunc("/api/custom_delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		id := strings.TrimSpace(strOf(body["id"]))
		customMu.Lock()
		list := loadCustomSources()
		var kept []customSource
		var removed *customSource
		for i := range list {
			if list[i].ID == id {
				cs := list[i]
				removed = &cs
			} else {
				kept = append(kept, list[i])
			}
		}
		if removed != nil {
			saveCustomSources(kept)
			os.Remove(extCachePath(removed.key()))
			stateMu.Lock()
			delete(extErrors, removed.key())
			stateMu.Unlock()
		}
		customMu.Unlock()
		if removed == nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": "没找到这个源"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hint": "已删除"})
	})

	mux.HandleFunc("/api/clash.yaml", func(w http.ResponseWriter, r *http.Request) {
		// 给 Clash Verge 的下载器绕路用：面板直接下发 YAML 文件，Verge 里以本地文件导入
		nodes, _ := aggregateNodes(false)
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''%E5%85%8D%E8%B4%B9%E5%85%AC%E7%9B%8A%E8%8A%82%E7%82%B9.yaml")
		w.Write([]byte(buildClashYAML(nodes)))
	})

	mux.HandleFunc("/api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hint": "后台服务即将退出"})
		go func() {
			time.Sleep(500 * time.Millisecond)
			logf("收到面板退出请求，后台服务退出")
			exitService()
		}()
	})

	mux.HandleFunc("/api/reset_token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		resetToken()
		logf("订阅密钥已重置，旧地址失效")
		writeJSON(w, 200, map[string]any{"ok": true, "sub_url": subURL(), "hint": "已生成新订阅地址，旧地址立即作废"})
	})

	mux.HandleFunc("/api/proxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]any{"error": "POST only"})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		p := strings.TrimSpace(strOf(body["proxy"]))
		if p != "" && !strings.Contains(p, "://") {
			p = "http://" + p
		}
		if p != "" {
			if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
				writeJSON(w, 200, map[string]any{"ok": false, "error": "只支持 HTTP 代理，格式如 http://127.0.0.1:7890"})
				return
			}
			if strings.Contains(p, ":8765") {
				writeJSON(w, 200, map[string]any{"ok": false, "error": "这是面板自己的端口，不能填"})
				return
			}
		}
		setUserProxy(p)
		writeJSON(w, 200, map[string]any{"ok": true, "hint": "已保存"})
	})

	mux.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(403)
		w.Write([]byte("订阅地址无效：请打开启动器或状态页复制带密钥的订阅地址（老地址已停用）"))
	})
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		given := strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
		if given != currentToken() {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(403)
			w.Write([]byte("订阅地址无效：请打开启动器或状态页复制带密钥的订阅地址（老地址已停用）"))
			return
		}
		ua := strings.ToLower(r.UserAgent())
		if strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") {
			nodes, _ := aggregateNodes(false)
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
			w.Write([]byte(buildClashYAML(nodes)))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(buildSubV2ray()))
	})

	// 后台定时刷新：每 3 小时把全部源再更新一遍，后台一直开着也不会用到过期节点
	go func() {
		t := time.NewTicker(3 * time.Hour)
		defer t.Stop()
		for range t.C {
			if tryStartSlots() {
				_, errs := refreshSlotsSync()
				endSlots(errs)
			}
			if tryStartExt() {
				refreshExtAllSync()
				endExt()
			}
			logf("定时刷新完成")
		}
	}()

	// 启动即自动刷新一遍全部源（后台进行）：保证每次打开用的都是新节点
	go func() {
		if tryStartSlots() {
			_, errs := refreshSlotsSync()
			endSlots(errs)
		}
		if tryStartExt() {
			refreshExtAllSync()
			endExt()
		}
		logf("启动自动刷新完成")
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", panelPort)
	logf("后台服务启动 -> http://%s/sub/****（密钥不记日志）", addr)
	srv := &http.Server{Addr: addr, Handler: mux}
	if err := serveWithTray(srv); err != nil {
		logf("服务退出：%v", err)
		return 1
	}
	return 0
}

const statusHTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>免费公益节点面板</title>
<style>
body{font-family:"Microsoft YaHei",system-ui,sans-serif;background:#f3f5fb;color:#172033;margin:0}
.wrap{max-width:920px;margin:0 auto;padding:22px 14px 40px}
.card{background:#fff;border-radius:14px;padding:18px 20px;margin-top:14px;box-shadow:0 4px 16px rgba(20,30,60,.07)}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:0 0 10px}
code{background:#eef2ff;padding:9px 11px;border-radius:8px;display:block;word-break:break-all;margin:8px 0;font-size:14px}
button{border:0;border-radius:9px;padding:9px 15px;font-weight:700;cursor:pointer;background:#2563eb;color:#fff;margin:4px 6px 4px 0}
button.gray{background:#eef1f7;color:#24314f}button.small{padding:4px 10px;font-size:12px}
.tip{color:#5b6478;font-size:13.5px;line-height:1.7}
input{padding:9px;border:2px solid #dbe2f0;border-radius:9px}
#banner{border-radius:12px;padding:12px 16px;margin-top:14px;font-weight:700;display:none}
#banner.busy{display:block;background:#fff7e5;color:#8a5a00;border:1px solid #f2d492}
#banner.done{display:block;background:#e9f9ee;color:#137333;border:1px solid #a9dfbb}
.ext{border-top:1px dashed #e2e7f2;padding:8px 0;font-size:14px;line-height:1.8}
.src{font-weight:700;margin:14px 0 6px;color:#24314f}
.node{display:flex;align-items:center;gap:8px;padding:6px 0;border-top:1px solid #f0f2f8;font-size:13.5px;flex-wrap:wrap}
.badge{background:#eef2ff;border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700}
.addr{color:#5b6478;word-break:break-all}
</style></head>
<body><div class="wrap">
<h1>🚀 免费公益节点面板</h1>
<p class="tip">服务在后台无窗口运行，你只管用这个页面操作。每次双击程序都会自动把全部内置源刷新一遍，本页会自动显示进度，刷新时不用等、可以先干别的。</p>
<div id="banner"></div>
<div id="ubanner" style="display:none"></div>
<div class="card"><h2>订阅地址（v2rayN / Clash / 手机客户端通用，格式自动适配）</h2>
<code id="sub">{{SUB}}</code>
<button onclick="cp(currentSub(),this)">复制订阅地址</button>
<button class="gray" id="eyeBtn" onclick="toggleEye()">👁 显示完整地址</button>
<button class="gray" onclick="resetKey()">🔑 重置订阅密钥</button>
<a href="/api/clash.yaml" download><button type="button" class="gray">⬇ 下载 Clash 配置文件</button></a>
<a id="clashImport" href="#"><button type="button">⚡ 一键导入 Clash Verge</button></a>
<p class="tip">地址默认打码显示（录屏、截图都不会泄露），点小眼睛才显示完整地址；复制按钮复制的是完整地址。地址带访问密钥，只填你自己的客户端，别外传。点「重置订阅密钥」会生成新地址、旧地址立即作废，客户端里记得换成新地址。电脑关机或后台被停掉时，订阅更新不了，节点还能用缓存顶一阵。Clash Verge 里更新订阅报 502 之类的错时，点上面「⬇ 下载 Clash 配置文件」，在 Verge 订阅页点「新建」选「本地」导入这个文件，节点完全一样。装了 Clash Verge 的话，也可以直接点「⚡ 一键导入 Clash Verge」自动打开 Verge 导入；点了没反应说明 Verge 没装或没启动，用复制地址手动导入即可。</p></div>
<div class="card"><h2>节点总览</h2>
<p id="stats">加载中…</p>
<button onclick="post('/api/fetch_all')">🔄 刷新免费公益节点池</button>
<button onclick="post('/api/ext_refresh')">🌐 更新外部源并测活</button>
<button class="gray" onclick="shutdownSvc()">⏹ 退出后台</button>
<button class="gray" onclick="copyDiag(this)">📋 复制诊断信息</button>
<p class="tip" id="rstatus"></p>
<p class="tip">遇到问题时点「📋 复制诊断信息」，把内容粘贴到 GitHub Issue 或发给作者，定位最快（不含订阅地址和密钥）。</p>
<p class="tip">拉不到源时，可填你正在运行的代理再刷新，如 http://127.0.0.1:10808 或 http://127.0.0.1:7890：</p>
<input id="px" style="width:60%" placeholder="留空 = 直连+镜像">
<button class="gray" onclick="saveProxy()">保存代理设置</button>
</div>
<div class="card"><h2>外部公共源（自动测活后保留）</h2><div id="extlist">加载中…</div></div>
<div class="card"><h2>自定义源（自己添加的订阅 / 节点列表）</h2>
<div id="cuslist">加载中…</div>
<p class="tip">在网上看到的订阅链接、或者每行一条节点链接的列表地址，都可以加进来：它会和内置源一起，在每次打开时自动更新、测活、去重，合并进上面同一个订阅地址。支持 base64 订阅和纯文本链接列表；Clash 专用的 YAML 订阅请先转换成 v2ray 格式再添加。</p>
<input id="cusName" style="width:26%" placeholder="名称（可不填）">
<input id="cusUrl" style="width:50%" placeholder="粘贴订阅链接 / 列表地址（http:// 或 https://）">
<button onclick="addCustom()">➕ 添加源</button>
</div>
<div class="card"><h2>⚠️ 公共节点使用注意事项</h2>
<ul class="tip" style="margin:0;padding-left:20px;line-height:1.95">
<li>公共节点是陌生人运营的服务器，你的流量要经过它：<b>不要用它登录重要账号</b>（网银、支付、主邮箱、社交主账号），不要在上面输密码、做转账支付。</li>
<li>浏览器提示「证书不安全 / 连接不是私密连接」时，<b>千万不要点继续访问</b>，关掉页面换一个节点。</li>
<li>不要用公共节点传公司文件、合同、私密照片等敏感内容；重要的事用你自己付费可信的机场或自建节点。</li>
<li>免费节点随时可能失效、变慢，个别还会弹广告：遇到要求安装证书、下载软件、输入账号密码的页面，一律关闭，不要理会。</li>
<li>重要账号都开启两步验证；公共节点单独用一个订阅分组，和付费机场分开，别混在一起自动切换。</li>
<li>重要场合（会议、考试、抢购）提前备好付费或自建的备用线路，不要只依赖免费节点。</li>
<li>只用于访问公开信息和学习交流，遵守当地法律法规，以及公司 / 学校的网络使用规定。</li>
</ul></div>
<div class="card"><h2>全部线路（已去重）<button class="small gray" id="nodesBtn" style="float:right" onclick="toggleNodes()">展开查看</button></h2>
<p class="tip">这里是每个节点的明细，一般不用看：订阅地址里已经包含全部节点。只有想单独复制某一条链接（比如发给手机）、或检查某个源贡献了哪些节点时，才需要展开。</p>
<div id="nodesWrap" style="display:none">
<input id="q" style="width:60%" placeholder="按名称 / 地址搜索过滤…" oninput="renderNodes()">
<div id="nodes">加载中…</div>
</div>
</div>
<p class="tip">怎么用：v2rayN 里「订阅 → 添加订阅分组」粘贴上面的地址，更新订阅即可，客户端会定时自己来拉新节点。手机和电脑连同一个 WiFi 时，手机客户端也能填这个地址（把地址里的 127.0.0.1 换成电脑的局域网 IP 不行，本服务只监听本机；手机使用请看说明里的办法）。后台每 3 小时还会自动刷新全部源。</p>
</div>
<script>
let NODES=[], wasBusy=false;
let SUBFULL='{{SUB}}', eyeOn=false;
function maskSub(u){let i=u.lastIndexOf('/sub/');return i<0?u:u.slice(0,i+5)+'••••••••••••'}
function currentSub(){return SUBFULL}
function showSub(){document.getElementById('sub').innerText=eyeOn?SUBFULL:maskSub(SUBFULL);document.getElementById('eyeBtn').innerText=eyeOn?'🙈 隐藏地址':'👁 显示完整地址';document.getElementById('clashImport').href='clash://install-config?url='+encodeURIComponent(SUBFULL)+'&name='+encodeURIComponent('免费公益节点')}
function toggleEye(){eyeOn=!eyeOn;showSub()}
function resetKey(){if(!confirm('确定要重置订阅密钥吗？\n旧订阅地址会立即失效，v2rayN / Clash 里需要改填新地址。'))return;fetch('/api/reset_token',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json()).then(j=>{if(j.sub_url){SUBFULL=j.sub_url;eyeOn=false;showSub();alert('已生成新订阅地址（已自动打码）。旧地址已作废，记得去客户端把订阅地址换成新的。')}else{alert(j.error||'重置失败')}}).catch(()=>alert('重置失败，请刷新页面重试'))}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function cp(t,btn){navigator.clipboard.writeText(t).then(()=>{let o=btn.innerText;btn.innerText='已复制';setTimeout(()=>btn.innerText=o,1200)})}
function post(u){fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(()=>setTimeout(refresh,600))}
function saveProxy(){fetch('/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxy:document.getElementById('px').value})}).then(r=>r.json()).then(j=>alert(j.hint||j.error||'已保存'))}
function copyDiag(btn){fetch('/api/diag').then(r=>r.json()).then(j=>{cp(j.text,btn)}).catch(()=>alert('获取诊断信息失败，请刷新页面重试'))}
function shutdownSvc(){if(!confirm('确定要退出后台服务吗？\n退出后订阅暂时无法更新，重新双击「免费公益节点面板.exe」即可再启动。'))return;fetch('/api/shutdown',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(()=>{document.body.innerHTML='<div style="max-width:640px;margin:90px auto;text-align:center"><h2>后台服务已退出</h2><p class="tip">右下角托盘图标会随之消失。想再用时，双击「免费公益节点面板.exe」即可。</p></div>'}).catch(()=>{})}
function addCustom(){let name=document.getElementById('cusName').value.trim(),u=document.getElementById('cusUrl').value.trim();if(!u){alert('先粘贴订阅链接或列表地址');return}fetch('/api/custom_add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,url:u})}).then(r=>r.json()).then(j=>{if(j.ok){document.getElementById('cusUrl').value='';document.getElementById('cusName').value='';alert(j.hint||'已添加');setTimeout(refresh,800)}else{alert(j.error||'添加失败')}}).catch(()=>alert('添加失败，请重试'))}
function delCustom(id){if(!confirm('确定删除这个自定义源吗？它贡献的节点会从订阅里消失。'))return;fetch('/api/custom_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})}).then(r=>r.json()).then(j=>{if(j.ok){refresh()}else{alert(j.error||'删除失败')}}).catch(()=>alert('删除失败，请重试'))}
let nodesOpen=false, lastNodesTotal=0;
function toggleNodes(){nodesOpen=!nodesOpen;document.getElementById('nodesWrap').style.display=nodesOpen?'block':'none';updNodesBtn()}
function updNodesBtn(){let b=document.getElementById('nodesBtn');if(nodesOpen){b.innerText='收起'}else{b.innerText='展开查看'+(lastNodesTotal>0?'（共 '+lastNodesTotal+' 条）':'')}}
function renderNodes(){
  let q=document.getElementById('q').value.trim().toLowerCase();
  let html='', lastSrc='__none__', shown=0;
  NODES.forEach((n,i)=>{
    if(q && (n.name+' '+n.server+' '+n.source).toLowerCase().indexOf(q)<0) return;
    shown++;
    if(n.source!==lastSrc){html+='<div class="src">'+esc(n.source||'其他')+'</div>';lastSrc=n.source}
    html+='<div class="node"><span class="badge">'+esc(n.protocol)+'</span><span>'+esc(n.name)+'</span>'+
      '<span class="addr">'+esc(n.server)+':'+esc(n.port)+'</span>'+
      (n.ms?'<span class="addr">⚡'+n.ms+'ms</span>':'')+
      '<span>'+(n.v2n?'v2rayN ✅':'v2rayN ❌（仅 Clash）')+'</span>'+
      (n.link?'<button class="small gray" onclick="cp(NODES['+i+'].link,this)">复制链接</button>':'')+'</div>';
  });
  document.getElementById('nodes').innerHTML = shown? html : '<p class="tip">暂无节点，刷新完成后会自动出现。</p>';
}
function refreshUpd(){
  fetch('/api/tools').then(r=>r.json()).then(j=>{
    let ub=document.getElementById('ubanner');
    if(j.update_available && localStorage.getItem('upd_dismissed')!==j.update_available){
      ub.style.display='block'; ub.className='done';
      ub.innerHTML='🎉 有新版本 '+esc(j.update_available)+' 可用（你现在是 '+esc(j.release||'')+'），<a href="'+esc(j.release_url)+'" target="_blank">点此去 GitHub 下载新版</a>　<button class="small gray" id="updX">忽略此版本</button>';
      document.getElementById('updX').onclick=function(){localStorage.setItem('upd_dismissed',j.update_available);ub.style.display='none'};
    } else { ub.style.display='none' }
  }).catch(()=>{});
}
function refresh(){
  refreshUpd();
  fetch('/api/status').then(r=>r.json()).then(j=>{
    let parts=[]; for(let k in j.counts){parts.push(k+' '+j.counts[k])}
    document.getElementById('stats').innerHTML='订阅里共 <b>'+j.total+'</b> 个节点（v2rayN 口径）：'+esc(parts.join(' · '));
    let busy=j.slots_refreshing||j.ext_refreshing, b=document.getElementById('banner');
    document.getElementById('rstatus').innerText=(j.slots_refreshing?'免费公益节点池刷新中… ':'')+(j.ext_refreshing?'外部源测活中（约 1-2 分钟）…':'');
    if(busy){b.className='busy';b.innerText='⏳ 正在后台更新节点，完成后本页会自动刷新列表，你可以先去用已有的节点。';wasBusy=true}
    else if(wasBusy){b.className='done';b.innerText='✅ 更新完成：现在订阅里共 '+j.total+' 个节点，去客户端点一下「更新订阅」就能用上。';wasBusy=false}
    else{b.className='';b.style.display='none'}
  }).catch(()=>{});
  fetch('/api/ext').then(r=>r.json()).then(j=>{
    if(j.proxy_cfg!==undefined && document.activeElement.id!=='px') document.getElementById('px').value=j.proxy_cfg||'';
    let row=e=>{
      let s='<b>'+esc(e.label)+'</b>：';
      if(e.total!=null){s+='共 '+e.total+' 个 → 留下 <b>'+e.keep+'</b> 个 · '+esc(e.fetched||'')+' 更新'}
      else{s+='暂无缓存，等更新完成'}
      if(e.error){s+=' · <span style="color:#c0392b">最近一次失败：'+esc(e.error)+'</span>'}
      return s;
    };
    document.getElementById('extlist').innerHTML=j.ext.filter(e=>!e.custom).map(e=>'<div class="ext">'+row(e)+'</div>').join('');
    let cus=j.ext.filter(e=>e.custom);
    document.getElementById('cuslist').innerHTML=cus.length?cus.map(e=>'<div class="ext">'+row(e)+' <button class="small gray" onclick="delCustom(\''+e.id+'\')">删除</button><br><span class="addr">'+esc(e.url)+'</span></div>').join(''):'<p class="tip">还没有添加自定义源，在下面粘贴地址添加。</p>';
  }).catch(()=>{});
  fetch('/api/nodes').then(r=>r.json()).then(j=>{NODES=j.nodes||[];lastNodesTotal=j.total||0;renderNodes();updNodesBtn()}).catch(()=>{});
}
showSub(); refresh(); setInterval(refresh,4000);
</script>
</body></html>`
