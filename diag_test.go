package main

import (
	"strings"
	"testing"
)

// 诊断信息会粘贴到公开 Issue，订阅密钥绝不能出现在里面（含旧日志里的完整地址）
func TestDiagRedactsSubscriptionToken(t *testing.T) {
	sample := "10:04 后台服务启动 -> http://127.0.0.1:8765/sub/_eqq9qIPuRauH3sCTyaRFg\n其他日志一行"
	out := subTokenRe.ReplaceAllString(sample, "/sub/****")
	if strings.Contains(out, "_eqq9qIPuRauH3sCTyaRFg") {
		t.Errorf("密钥没有被打码：%s", out)
	}
	if !strings.Contains(out, "/sub/****") {
		t.Errorf("应把地址替换为打码形式：%s", out)
	}
	if !strings.Contains(out, "其他日志一行") {
		t.Error("不相关的日志行不应被改动")
	}
}
