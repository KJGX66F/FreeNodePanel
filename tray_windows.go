//go:build windows

package main

// Windows 系统托盘：后台服务运行时在右下角通知区域显示图标。
// 绿图标 = 运行中；橙图标 = 正在更新节点。鼠标悬停显示状态和节点数；
// 双击打开面板；右键菜单：打开面板 / 立即刷新全部源 / 退出后台。
// 纯 syscall 实现，无第三方依赖。托盘初始化失败时自动退回无托盘模式，不影响服务本身。

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

//go:embed tray_green.ico
var trayGreenICO []byte

//go:embed tray_orange.ico
var trayOrangeICO []byte

const (
	wmDestroy        = 0x0002
	wmCommand        = 0x0111
	wmLButtonDblClk  = 0x0203
	wmRButtonUp      = 0x0205
	wmApp            = 0x8000
	wmTrayCallback   = wmApp + 1
	wmTrayUpdate     = wmApp + 2
	wmServeFailed    = wmApp + 3
	nimAdd           = 0x00000000
	nimModify        = 0x00000001
	nimDelete        = 0x00000002
	nifMessage       = 0x00000001
	nifIcon          = 0x00000002
	nifTip           = 0x00000004
	mfString         = 0x00000000
	mfSeparator      = 0x00000800
	tpmLeftAlign     = 0x0000
	tpmBottomAlign   = 0x0020
	tpmRightButton   = 0x0002
	tpmReturnCmd     = 0x0100
	imageIcon        = 1
	lrLoadFromFile   = 0x00000010
	lrDefaultSize    = 0x00000040
	hwndMessage      = ^uintptr(2) // HWND_MESSAGE = -3
	idMenuOpen       = 1001
	idMenuRefresh    = 1002
	idMenuQuit       = 1003
)

var (
	shell32               = syscall.NewLazyDLL("shell32.dll")
	user32T               = syscall.NewLazyDLL("user32.dll")
	kernel32T             = syscall.NewLazyDLL("kernel32.dll")
	procShellNotifyIcon   = shell32.NewProc("Shell_NotifyIconW")
	procRegisterClassEx   = user32T.NewProc("RegisterClassExW")
	procCreateWindowEx    = user32T.NewProc("CreateWindowExW")
	procDefWindowProc     = user32T.NewProc("DefWindowProcW")
	procGetMessage        = user32T.NewProc("GetMessageW")
	procTranslateMessage  = user32T.NewProc("TranslateMessage")
	procDispatchMessage   = user32T.NewProc("DispatchMessageW")
	procPostQuitMessage   = user32T.NewProc("PostQuitMessage")
	procDestroyWindow     = user32T.NewProc("DestroyWindow")
	procCreatePopupMenu   = user32T.NewProc("CreatePopupMenu")
	procAppendMenu        = user32T.NewProc("AppendMenuW")
	procTrackPopupMenu    = user32T.NewProc("TrackPopupMenu")
	procGetCursorPos      = user32T.NewProc("GetCursorPos")
	procSetForegroundWnd  = user32T.NewProc("SetForegroundWindow")
	procPostMessage       = user32T.NewProc("PostMessageW")
	procRegisterWindowMsg = user32T.NewProc("RegisterWindowMessageW")
	procLoadImage         = user32T.NewProc("LoadImageW")
	procGetModuleHandle   = kernel32T.NewProc("GetModuleHandleW")
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UTimeout         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type point struct{ X, Y int32 }

type winMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

var tray struct {
	hwnd       uintptr
	srv        *http.Server
	greenIcon  uintptr
	orangeIcon uintptr
	wmTaskbar  uint32
	mu         sync.Mutex
	busy       bool
	total      int
	quitByUser bool
}

// 必须保存在包级变量里，防止回调被 GC 回收
var trayWndProcPtr = syscall.NewCallback(trayWndProc)

func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func loadTrayIcon(data []byte, name string) uintptr {
	p := filepath.Join(dataDir, name)
	if _, err := os.Stat(p); err != nil {
		os.WriteFile(p, data, 0o644)
	}
	h, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(utf16(p))), imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
	return h
}

func trayTipText() string {
	tray.mu.Lock()
	defer tray.mu.Unlock()
	if tray.busy {
		return "免费公益节点面板：正在更新节点…"
	}
	if tray.total > 0 {
		return fmt.Sprintf("免费公益节点面板：运行中（共 %d 个节点）", tray.total)
	}
	return "免费公益节点面板：运行中"
}

func trayNotify(flags uint32) {
	icon := tray.greenIcon
	tray.mu.Lock()
	if tray.busy {
		icon = tray.orangeIcon
	}
	tray.mu.Unlock()
	var nid notifyIconData
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = tray.hwnd
	nid.UID = 1
	nid.UFlags = nifMessage | nifIcon | nifTip
	nid.UCallbackMessage = wmTrayCallback
	nid.HIcon = icon
	tip, _ := syscall.UTF16FromString(trayTipText())
	if len(tip) > 127 {
		tip = tip[:127]
	}
	copy(nid.SzTip[:], tip)
	procShellNotifyIcon.Call(uintptr(flags), uintptr(unsafe.Pointer(&nid)))
}

// exitService 面板「退出后台」按钮调用：先删托盘图标，再结束进程
func exitService() {
	if tray.hwnd != 0 {
		var nid notifyIconData
		nid.CbSize = uint32(unsafe.Sizeof(nid))
		nid.HWnd = tray.hwnd
		nid.UID = 1
		procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	}
	os.Exit(0)
}

// triggerFullRefresh 与面板按钮等价：两路源都触发一次（已在刷新会自动跳过）
func triggerFullRefresh() {
	if tryStartSlots() {
		go func() {
			_, errs := refreshSlotsSync()
			endSlots(errs)
		}()
	}
	if tryStartExt() {
		go func() {
			defer endExt()
			refreshExtAllSync()
		}()
	}
}

func showTrayMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	procAppendMenu.Call(menu, mfString, idMenuOpen, uintptr(unsafe.Pointer(utf16("打开面板"))))
	procAppendMenu.Call(menu, mfString, idMenuRefresh, uintptr(unsafe.Pointer(utf16("立即刷新全部源"))))
	procAppendMenu.Call(menu, mfSeparator, 0, 0)
	procAppendMenu.Call(menu, mfString, idMenuQuit, uintptr(unsafe.Pointer(utf16("退出后台"))))
	var pt point
	procSetForegroundWnd.Call(hwnd)
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	ret, _, _ := procTrackPopupMenu.Call(menu, tpmLeftAlign|tpmBottomAlign|tpmRightButton|tpmReturnCmd,
		uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	procPostMessage.Call(hwnd, 0, 0, 0) // WM_NULL：让菜单正确收起（系统已知小毛病）
	switch ret {
	case idMenuOpen:
		openBrowser(base + "/")
	case idMenuRefresh:
		triggerFullRefresh()
	case idMenuQuit:
		quitFromTray()
	}
}

func quitFromTray() {
	tray.mu.Lock()
	tray.quitByUser = true
	tray.mu.Unlock()
	var nid notifyIconData
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = tray.hwnd
	nid.UID = 1
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	if tray.srv != nil {
		tray.srv.Close()
	}
	procDestroyWindow.Call(tray.hwnd)
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayCallback:
		switch lParam {
		case wmLButtonDblClk:
			openBrowser(base + "/")
		case wmRButtonUp:
			showTrayMenu(hwnd)
		}
		return 0
	case wmTrayUpdate:
		trayNotify(nimModify)
		return 0
	case wmServeFailed:
		notifyUser("后台服务启动失败", "8765 端口可能被其他程序占用。\n\n详细日志在程序旁边的 data\\server.log。")
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	default:
		if tray.wmTaskbar != 0 && msg == uintptr(tray.wmTaskbar) {
			// 资源管理器重启后托盘图标会消失，重新添加
			trayNotify(nimAdd)
			return 0
		}
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wParam, lParam)
	return r
}

// trayPoller 每 3 秒看一次刷新状态和节点数，有变化就通知托盘窗口换图标/提示
func trayPoller() {
	var lastBusy, lastTotal = false, -1
	for {
		time.Sleep(3 * time.Second)
		if tray.hwnd == 0 {
			return
		}
		stateMu.Lock()
		busy := slotsRefreshing || extRefreshing
		stateMu.Unlock()
		total, _ := statusCounts()
		if busy != lastBusy || total != lastTotal {
			lastBusy, lastTotal = busy, total
			tray.mu.Lock()
			tray.busy, tray.total = busy, total
			tray.mu.Unlock()
			procPostMessage.Call(tray.hwnd, wmTrayUpdate, 0, 0)
		}
	}
}

// serveWithTray Windows 版：托盘消息循环与 HTTP 服务并行；托盘不可用时退回普通监听
func serveWithTray(srv *http.Server) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tray.srv = srv

	hInst, _, _ := procGetModuleHandle.Call(0)
	className := utf16("FreeNodePanelTrayWnd")
	var wc wndClassEx
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = trayWndProcPtr
	wc.HInstance = hInst
	wc.LpszClassName = className
	if atom, _, _ := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		logf("托盘窗口类注册失败，退回无托盘模式")
		return srv.ListenAndServe()
	}
	hwnd, _, _ := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16(""))), 0, 0, 0, 0, 0, hwndMessage, 0, hInst, 0)
	if hwnd == 0 {
		logf("托盘窗口创建失败，退回无托盘模式")
		return srv.ListenAndServe()
	}
	tray.hwnd = hwnd
	if r, _, _ := procRegisterWindowMsg.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated")))); r != 0 {
		tray.wmTaskbar = uint32(r)
	}
	tray.greenIcon = loadTrayIcon(trayGreenICO, "tray_green.ico")
	tray.orangeIcon = loadTrayIcon(trayOrangeICO, "tray_orange.ico")
	trayNotify(nimAdd)
	logf("系统托盘图标已显示")

	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		errCh <- err
		if err != nil && err != http.ErrServerClosed {
			procPostMessage.Call(tray.hwnd, wmServeFailed, 0, 0)
		}
	}()
	go trayPoller()

	var m winMsg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 || ret == ^uintptr(0) {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	default:
	}
	return nil
}
