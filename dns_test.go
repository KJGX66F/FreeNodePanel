package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// 说明：这台开发沙箱的网络策略禁止「未连接 UDP 套接字向高位端口 sendto」，
// 假 DNS 服务器没法用普通方式回 UDP 包（connected 校验又要求回包源端口
// 必须等于服务器端口），所以端到端解析测试走 TCP 传输——生产 Dial 本来
// 就按 Resolver 要求支持 TCP，这条路径与 UDP 共用同一套选服务器/拨号逻辑；
// UDP 方向另用「Dial 定向测试」覆盖：断言 Dial 忽略坏地址、查询确实
// 发到了我们指定的服务器。真机 UDP/53 的实际表现以真机复测为准。

// buildFakeDNSResponse 按查询构造最小合法应答：A 查询给 answerIP，
// 其它类型给 NOERROR 空应答。
func buildFakeDNSResponse(q []byte, answerIP string) []byte {
	if len(q) < 12 {
		return nil
	}
	// 定位问题段结尾：标签序列以 0 结束，其后是 QTYPE(2)+QCLASS(2)
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i+5 > len(q) {
		return nil
	}
	qend := i + 5
	qtype := binary.BigEndian.Uint16(q[i+1 : i+3])
	resp := append([]byte{}, q[:qend]...)
	resp[2], resp[3] = 0x81, 0x80              // QR=1、RD/RA、NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT（清掉查询里可能带的计数）
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT（查询带 EDNS OPT，应答不带）
	if qtype == 1 {                            // A
		ip := net.ParseIP(answerIP).To4()
		if ip == nil {
			return nil
		}
		binary.BigEndian.PutUint16(resp[6:8], 1)
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		resp = append(resp, ip...)
	}
	return resp
}

// startFakeTCPDNS 起一个 TCP 假 DNS 服务器（DNS-over-TCP 的两字节长度前缀分帧），
// A 查询一律应答 answerIP。返回端口与关闭函数。
func startFakeTCPDNS(t *testing.T, answerIP string) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("假 DNS(TCP) 监听失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				for {
					if _, err := io.ReadFull(c, hdr); err != nil {
						return
					}
					qlen := int(binary.BigEndian.Uint16(hdr))
					q := make([]byte, qlen)
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					resp := buildFakeDNSResponse(q, answerIP)
					if resp == nil {
						return
					}
					var out [2]byte
					binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
					if _, err := c.Write(append(out[:], resp...)); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

// startFakeUDPSink 起一个只收不答的 UDP 监听，把收到的每个查询发进 channel。
func startFakeUDPSink(t *testing.T) (int, <-chan []byte, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("假 DNS(UDP) 监听失败: %v", err)
	}
	ch := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			ch <- append([]byte{}, buf[:n]...)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, ch, func() { pc.Close() }
}

// 以假 TCP DNS 服务器做端到端解析，并验证 Dial 忽略 Resolver 递来的坏 addr。
// 测试用包装 Dial 把传输强制成 tcp（沙箱 UDP 回包受限，见文件头说明），
// 服务器轮换与拨号仍走生产 dnsDialFunc 本体。
func TestResolverEndToEndTCP(t *testing.T) {
	port, stop := startFakeTCPDNS(t, "203.0.113.7")
	defer stop()

	old := dnsPort
	dnsPort = strconv.Itoa(port)
	defer func() { dnsPort = old }()

	prod := dnsDialFunc([]string{"127.0.0.1"})
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// addr 故意传坏地址，断言生产 Dial 不理它、只拨自己的服务器列表
		return prod(ctx, "tcp", "[::1]:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ip4", "example.test")
	if err != nil {
		t.Fatalf("端到端解析失败: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.7" {
		t.Fatalf("解析结果不对: %v（应为 [203.0.113.7]）", ips)
	}
}

// 第一台服务器是死的（TCP 连接被拒）时，Dial 内的逐台尝试要落到下一台。
func TestDialSkipsDeadServerTCP(t *testing.T) {
	port, stop := startFakeTCPDNS(t, "203.0.113.9")
	defer stop()

	old := dnsPort
	dnsPort = strconv.Itoa(port)
	defer func() { dnsPort = old }()

	// 127.0.0.2 在本机 loopback /8 内但没人监听该端口，连接立即被拒；
	// 第二台 127.0.0.1 才是假服务器。
	prod := dnsDialFunc([]string{"127.0.0.2", "127.0.0.1"})
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return prod(ctx, "tcp", addr)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ip4", "example.test")
	if err != nil {
		t.Fatalf("坏服务器在前时解析失败: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.9" {
		t.Fatalf("解析结果不对: %v（应为 [203.0.113.9]）", ips)
	}
}

// UDP 方向的定向测试：生产 Dial 拿着坏的 [::1]:53 也要拨到指定服务器，
// 在它给出的连接上写一个查询，假服务器应当原样收到（按事务 ID 核对）。
func TestDNSDialIgnoresAddrUDP(t *testing.T) {
	port, ch, stop := startFakeUDPSink(t)
	defer stop()

	old := dnsPort
	dnsPort = strconv.Itoa(port)
	defer func() { dnsPort = old }()

	dial := dnsDialFunc([]string{"127.0.0.1"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dial(ctx, "udp", "[::1]:53")
	if err != nil {
		t.Fatalf("Dial 失败: %v", err)
	}
	defer conn.Close()
	// 最小查询：ID=0xbeef，RD，QD=1，根域名 A 查询
	query := []byte{0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("在 Dial 出的连接上写查询失败: %v", err)
	}
	select {
	case got := <-ch:
		if len(got) < 2 || got[0] != 0xbe || got[1] != 0xef {
			t.Fatalf("假服务器收到的不是我们发的查询: % x", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("假服务器没收到查询——Dial 没有拨向指定服务器")
	}
}

func TestParseDNSServers(t *testing.T) {
	got := parseDNSServers(" 223.5.5.5, not-an-ip ,fe80::1%wlan0, 8.8.8.8 ,,")
	want := []string{"223.5.5.5", "fe80::1", "8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("parseDNSServers = %v，应为 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseDNSServers = %v，应为 %v", got, want)
		}
	}
	if got := parseDNSServers(""); len(got) != 0 {
		t.Fatalf("空输入应返回空，得到 %v", got)
	}
}
