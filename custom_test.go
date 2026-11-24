package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempDataDir 把 dataDir/cacheDir 临时指向一个空目录，测完恢复。
// 自定义源的增删改都落盘到 dataDir，不用它测不到真实的落盘行为。
func withTempDataDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldData, oldCache := dataDir, cacheDir
	dataDir = dir
	cacheDir = filepath.Join(dir, "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dataDir, cacheDir = oldData, oldCache })
}

func TestDeleteCustomSource(t *testing.T) {
	withTempDataDir(t)
	saveCustomSources([]customSource{
		{ID: "aaa111", Name: "源A", URL: "https://example.com/a.txt"},
		{ID: "bbb222", Name: "源B", URL: "https://example.com/b.txt"},
	})

	// 删不存在的：返回 false，原列表不动
	if deleteCustomSource("不存在") {
		t.Error("删不存在的源应返回 false")
	}
	if got := loadCustomSources(); len(got) != 2 {
		t.Fatalf("删不存在的源不应动列表，得到 %d 条", len(got))
	}

	// 删掉一个：剩下一个，且落盘后的文件能重新读回
	if !deleteCustomSource("aaa111") {
		t.Error("删已有的源应返回 true")
	}
	got := loadCustomSources()
	if len(got) != 1 || got[0].ID != "bbb222" {
		t.Fatalf("删后应只剩源B，得到 %+v", got)
	}

	// 删光最后一个：文件应是 [] 而不是 null，读回仍是空列表
	if !deleteCustomSource("bbb222") {
		t.Error("删最后一个源应返回 true")
	}
	b, err := os.ReadFile(customFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Errorf("删光后文件应是 []，得到 %s", string(b))
	}
	if got := loadCustomSources(); len(got) != 0 {
		t.Errorf("删光后读回应是空列表，得到 %+v", got)
	}

	// 空 ID、带空格的 ID 都不删
	if deleteCustomSource("") || deleteCustomSource("  ") {
		t.Error("空 ID 不应删掉任何东西")
	}
}

func TestProgressPct(t *testing.T) {
	cases := []struct{ done, total, want int }{
		{0, 10, 0},
		{5, 10, 50},
		{10, 10, 100},
		{12, 10, 100}, // 超过总数时钳到 100，不会溢出
		{0, 0, 0},     // 总数为 0 不除零
		{3, 7, 42},
	}
	for _, c := range cases {
		if got := progressPct(c.done, c.total); got != c.want {
			t.Errorf("progressPct(%d, %d) = %d，期望 %d", c.done, c.total, got, c.want)
		}
	}
}
