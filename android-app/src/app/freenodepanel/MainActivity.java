package app.freenodepanel;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.DownloadListener;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * 免费公益节点面板 · 安卓原型壳
 *
 * 职责只有三件：
 *  1) 启动前台服务 PanelService（由它拉起并看护 Go 服务进程、挂常驻通知，
 *     v0.1.2 起从 Activity 迁出，避免切到别的 App 后进程被系统回收）；
 *  2) 轮询面板地址，通了就用全屏 WebView 显示面板；
 *  3) 拦截 WebView 处理不了的链接（clash:// 一键导入、配置文件下载、外链）。
 *
 * 与电脑版一致：关掉/划掉本界面不杀服务进程；停服务用面板里的「⏹ 退出后台」
 *（服务进程退出后 PanelService 会察觉并自停、撤掉常驻通知）。
 */
public class MainActivity extends Activity {

    private static final String PANEL_BASE = "http://127.0.0.1:8765";
    private static final String PANEL_URL = PANEL_BASE + "/";
    private static final int MAX_POLLS = 40; // 40 × 500ms ≈ 20 秒

    private final Handler ui = new Handler(Looper.getMainLooper());
    private FrameLayout root;
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        root = new FrameLayout(this);
        setContentView(root);
        requestNotificationPermission();
        startFlow();
    }

    /** 安卓 13+ 显示通知要运行时授权；不给也不拦主流程，只影响通知在通知栏的可见性。 */
    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            try {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1001);
            } catch (Exception ignored) {
            }
        }
    }

    // ---------------- 启动流程 ----------------

    private void startFlow() {
        showLoading("正在启动节点服务…");
        startPanelService();
        new Thread(new Runnable() {
            @Override
            public void run() {
                pollUntilReady(0);
            }
        }).start();
    }

    /** 拉起进程与看护都归前台服务；已在运行时重复调用无副作用。 */
    private void startPanelService() {
        try {
            startForegroundService(new Intent(this, PanelService.class));
        } catch (Exception e) {
            // 极少数系统限制下退回普通启动（服务内部仍会 startForeground）
            try {
                startService(new Intent(this, PanelService.class));
            } catch (Exception ignored) {
            }
        }
    }

    private void pollUntilReady(final int n) {
        if (panelReachable()) {
            ui.post(new Runnable() {
                @Override
                public void run() {
                    showWeb();
                }
            });
            return;
        }
        if (n >= MAX_POLLS) {
            ui.post(new Runnable() {
                @Override
                public void run() {
                    showError("节点服务 20 秒内没有响应。\n可能是启动失败，下面是服务日志的最后部分，可以截图反馈：");
                }
            });
            return;
        }
        try {
            Thread.sleep(500);
        } catch (InterruptedException ignored) {
        }
        pollUntilReady(n + 1);
    }

    private boolean panelReachable() {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(PANEL_URL).openConnection();
            c.setConnectTimeout(800);
            c.setReadTimeout(800);
            c.setRequestMethod("GET");
            return c.getResponseCode() == 200;
        } catch (Exception e) {
            return false;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    // ---------------- 界面状态 ----------------

    private void showLoading(String text) {
        root.removeAllViews();
        webView = null;
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER);
        ProgressBar bar = new ProgressBar(this);
        box.addView(bar);
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(16);
        tv.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = 24;
        box.addView(tv, lp);
        root.addView(box, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    private void showError(String text) {
        root.removeAllViews();
        webView = null;
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = 32;
        box.setPadding(pad, pad, pad, pad);
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(15);
        box.addView(tv);
        Button retry = new Button(this);
        retry.setText("重试");
        retry.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startFlow();
            }
        });
        box.addView(retry);
        TextView logTv = new TextView(this);
        logTv.setText(tailOfLog(30));
        logTv.setTextSize(11);
        logTv.setTypeface(android.graphics.Typeface.MONOSPACE);
        ScrollView sc = new ScrollView(this);
        sc.addView(logTv);
        box.addView(sc, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(box, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    private String tailOfLog(int maxLines) {
        File f = new File(getFilesDir(), "applog.txt");
        // 服务自己的 data/server.log 也一并看看（FNP_DATA_DIR 下）
        File svcLog = new File(getFilesDir(), "server.log");
        StringBuilder sb = new StringBuilder();
        appendTail(sb, f, maxLines);
        appendTail(sb, svcLog, maxLines);
        return sb.length() == 0 ? "（暂无日志）" : sb.toString();
    }

    private void appendTail(StringBuilder sb, File f, int maxLines) {
        if (!f.exists()) return;
        try {
            BufferedReader r = new BufferedReader(new FileReader(f));
            java.util.ArrayList<String> lines = new java.util.ArrayList<String>();
            String line;
            while ((line = r.readLine()) != null) lines.add(line);
            r.close();
            sb.append("—— ").append(f.getName()).append(" ——\n");
            int from = Math.max(0, lines.size() - maxLines);
            for (int i = from; i < lines.size(); i++) sb.append(lines.get(i)).append("\n");
        } catch (IOException ignored) {
        }
    }

    private void showWeb() {
        root.removeAllViews();
        webView = new WebView(this);
        WebSettings s = webView.getSettings();
        // UA 尾部加标记：面板页据此把「一键导入」切换成安卓版的 FlClash 深链接
        s.setUserAgentString(s.getUserAgentString() + " FreeNodePanel-Android");
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                return handleUrl(url);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return handleUrl(url);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame() && request.getUrl().toString().startsWith(PANEL_BASE)) {
                    showError("后台服务没有在运行（可能已被系统回收，或你刚点了「退出后台」）。\n点下面按钮重新启动：");
                }
            }
        });
        webView.setDownloadListener(new DownloadListener() {
            @Override
            public void onDownloadStart(String url, String userAgent, String contentDisposition,
                                        String mimetype, long contentLength) {
                handleUrl(url);
            }
        });
        root.addView(webView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        webView.loadUrl(PANEL_URL);
        maybePromptBatteryWhitelist();
    }

    // ---------------- 电池白名单引导 ----------------

    private static final String PREFS = "fnp_shell";
    private static final String KEY_BATTERY_PROMPTED = "battery_prompted";

    /**
     * 面板加载成功后最多弹一次：若系统还没给本 App 电池优化豁免，引导用户去允许。
     * 厂商系统在电池优化名单里照样可能冻后台进程，连累 FlClash / v2rayNG 拉订阅。
     * 已豁免或已提示过都不再打扰（标志位落 SharedPreferences）。
     */
    private void maybePromptBatteryWhitelist() {
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (pm == null) return;
            if (pm.isIgnoringBatteryOptimizations(getPackageName())) return;
            SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
            if (sp.getBoolean(KEY_BATTERY_PROMPTED, false)) return;
            sp.edit().putBoolean(KEY_BATTERY_PROMPTED, true).apply();
            new AlertDialog.Builder(this)
                    .setTitle("让订阅不断线")
                    .setMessage("系统可能会在后台停掉节点服务，FlClash / v2rayNG 就会拉不到订阅。\n\n建议把本 App 设为「不限制电量 / 允许后台运行」。")
                    .setPositiveButton("去设置", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface d, int w) {
                            openBatterySettings();
                        }
                    })
                    .setNegativeButton("以后再说", null)
                    .show();
        } catch (Exception ignored) {
        }
    }

    private void openBatterySettings() {
        try {
            Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            i.setData(Uri.parse("package:" + getPackageName()));
            startActivity(i);
            return;
        } catch (Exception ignored) {
        }
        try {
            startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
        } catch (Exception ignored) {
        }
    }

    /** 返回 true 表示已拦截处理，WebView 不再自行加载。 */
    private boolean handleUrl(String url) {
        if (url == null) return true;
        if (url.startsWith(PANEL_BASE + "/api/clash.yaml")) {
            downloadClashYaml(url);
            return true;
        }
        if (url.startsWith(PANEL_BASE) || url.startsWith("http://localhost:8765")) {
            return false; // 面板内部链接，WebView 自己加载
        }
        Uri uri = Uri.parse(url);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme();
        if ("http".equals(scheme) || "https".equals(scheme)) {
            // 外部网页链接（如说明/仓库链接）交给系统浏览器
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
            } catch (Exception ignored) {
            }
            return true;
        }
        if ("flclash".equals(scheme) || "clash".equals(scheme) || "clashmeta".equals(scheme)) {
            // 一键导入深链接交给系统：装了 FlClash / Clash Meta 的话由它们接住并打开导入确认
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
            } catch (ActivityNotFoundException e) {
                Toast.makeText(this,
                        "未检测到 FlClash，请先安装 FlClash，或复制订阅地址手动添加",
                        Toast.LENGTH_LONG).show();
            }
            return true;
        }
        // 其它认不出的链接才落到这里，引导用户走复制地址手动添加
        Toast.makeText(this,
                "「一键导入」是给电脑版 Clash 用的。安卓请点面板里的复制按钮复制订阅地址，再到 v2rayNG 里添加订阅。",
                Toast.LENGTH_LONG).show();
        return true;
    }

    private void downloadClashYaml(final String url) {
        Toast.makeText(this, "正在下载 Clash 配置文件…", Toast.LENGTH_SHORT).show();
        new Thread(new Runnable() {
            @Override
            public void run() {
                String result;
                try {
                    HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
                    c.setConnectTimeout(5000);
                    c.setReadTimeout(15000);
                    InputStream in = c.getInputStream();
                    File dir = getExternalFilesDir(null);
                    if (dir == null) dir = getFilesDir();
                    File out = new File(dir, "clash.yaml");
                    FileOutputStream fos = new FileOutputStream(out);
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) != -1) fos.write(buf, 0, n);
                    fos.close();
                    in.close();
                    result = "已保存到：" + out.getAbsolutePath();
                } catch (Exception e) {
                    result = "下载失败：" + e.getMessage();
                }
                final String msg = result;
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(MainActivity.this, msg, Toast.LENGTH_LONG).show();
                    }
                });
            }
        }).start();
    }

    // ---------------- 生命周期 ----------------

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed(); // 只退出界面，不杀服务（与电脑版一致）
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
