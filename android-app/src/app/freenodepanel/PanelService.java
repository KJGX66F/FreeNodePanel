package app.freenodepanel;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Build;
import android.os.IBinder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 免费公益节点面板 · 前台服务（v0.1.2 起）
 *
 * 为什么需要它：v0.1.1 由 Activity 直接拉起 Go 服务子进程，用户一切到
 * FlClash / v2rayNG，激进的厂商系统就可能把后台进程冻结或杀掉，外部
 * 客户端再访问 127.0.0.1:8765 就超时 / EOF（自家 WebView 反而没事，
 * 因为那时 App 在前台）。把进程看护迁到前台服务 + 常驻通知后，系统
 * 对进程的回收优先级大幅降低，相当于电脑版的托盘图标：通知在 = 服务在。
 *
 * 职责：
 *  1) startForeground 挂常驻通知（点按打开面板）；
 *  2) keeper 线程负责拉起 Go 子进程（FNP_DATA_DIR / FNP_NO_BROWSER /
 *     FNP_DNS 环境变量、applog.txt 转存，与 v0.1.1 的 Activity 逻辑一致）；
 *  3) 看护：亲手拉起的子进程一旦退出（用户在面板点了「⏹ 退出后台」、
 *     或进程被杀/崩溃），服务随之 stopSelf 并撤掉通知，杜绝「通知说在
 *     运行、其实已退出」的假状态；若服务被系统杀后以 START_STICKY 重启，
 *     keeper 发现端口没人应答会重新拉起进程，端口已被（幸存的）进程占着
 *     则只监视、不重复启动。
 */
public class PanelService extends Service {

    static final String PANEL_BASE = "http://127.0.0.1:8765";
    private static final String PANEL_URL = PANEL_BASE + "/";
    private static final String CHANNEL_ID = "fnp_node_service";
    private static final int NOTIF_ID = 8765;

    private static final long WATCH_INTERVAL_MS = 3000;
    private static final int DEAD_CHECKS_TO_STOP = 4;   // 曾活过、连续约 12 秒拉不到 → 判定已退出
    private static final long START_GRACE_MS = 45000;   // 冷启动宽限：迟迟绑不上端口才放弃

    private volatile Process goProcess;
    private volatile Thread keeper;
    private volatile boolean keeperStop;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // startForegroundService 后必须数秒内调用 startForeground，否则系统直接杀服务
        Notification n = buildNotification();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIF_ID, n);
        }
        ensureKeeper();
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        keeperStop = true;
        Thread k = keeper;
        if (k != null) k.interrupt();
        super.onDestroy();
    }

    // ---------------- 看护线程 ----------------

    private synchronized void ensureKeeper() {
        if (keeper != null && keeper.isAlive()) return;
        keeperStop = false;
        keeper = new Thread(new Runnable() {
            @Override
            public void run() {
                keeperLoop();
            }
        }, "fnp-keeper");
        keeper.start();
    }

    private void keeperLoop() {
        long startedAt = System.currentTimeMillis();
        boolean everAlive = panelReachable();
        if (!everAlive) {
            try {
                startGoProcess();
            } catch (Exception e) {
                appendLog("PanelService 拉起 Go 进程失败：" + e);
            }
        }
        int dead = 0;
        while (!keeperStop) {
            try {
                Thread.sleep(WATCH_INTERVAL_MS);
            } catch (InterruptedException e) {
                return;
            }
            // 亲手拉起的子进程已退出：无论退出原因，都收摊撤通知（见类注释）
            Process p = goProcess;
            if (p != null && !p.isAlive()) {
                appendLog("PanelService 检测到 Go 进程已退出，服务自停");
                shutdown();
                return;
            }
            if (panelReachable()) {
                everAlive = true;
                dead = 0;
                continue;
            }
            if (!everAlive) {
                if (System.currentTimeMillis() - startedAt > START_GRACE_MS) {
                    appendLog("PanelService 冷启动超时（端口迟迟无响应），服务自停");
                    shutdown();
                    return;
                }
                continue;
            }
            if (++dead >= DEAD_CHECKS_TO_STOP) {
                appendLog("PanelService 检测到面板端口持续无响应，服务自停");
                shutdown();
                return;
            }
        }
    }

    private void shutdown() {
        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        stopSelf();
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

    // ---------------- Go 子进程 ----------------

    private void startGoProcess() throws IOException {
        Process p = goProcess;
        if (p != null && p.isAlive()) return;
        File bin = new File(getApplicationInfo().nativeLibraryDir, "libfreenodepanel.so");
        if (!bin.exists()) {
            throw new IOException("找不到内置服务程序：" + bin.getAbsolutePath());
        }
        ProcessBuilder pb = new ProcessBuilder(bin.getAbsolutePath());
        pb.directory(getFilesDir());
        pb.environment().put("FNP_DATA_DIR", getFilesDir().getAbsolutePath());
        pb.environment().put("FNP_NO_BROWSER", "1");
        // 把手机当前时区传给 Go 服务：安卓没有 /etc/localtime，Go 子进程默认按 UTC
        // 显示时间（面板更新时间会差 8 小时）。配合 Go 构建时的 timetzdata 内嵌时区库，
        // TZ 命名时区才能被正确加载。取不到就不设置，保持 UTC 旧行为。
        try {
            String tz = java.util.TimeZone.getDefault().getID();
            if (tz != null && !tz.isEmpty()) {
                pb.environment().put("TZ", tz);
            }
        } catch (Exception ignored) {
        }
        // 把系统当前网络的 DNS 服务器传给 Go 服务：安卓上 Go 的纯解析器读不到
        // 系统 DNS（没有 /etc/resolv.conf），不传它就解析不了任何域名（v0.1.0 的坑）。
        // 取不到就不设置，Go 侧会用公共 DNS 兜底列表。
        String dns = systemDnsServers();
        if (dns != null && !dns.isEmpty()) {
            pb.environment().put("FNP_DNS", dns);
        }
        pb.redirectErrorStream(true);
        final Process proc = pb.start();
        goProcess = proc;
        // 持续把服务输出转存到 applog.txt（不读的话管道会堵住服务进程）
        final File logFile = new File(getFilesDir(), "applog.txt");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    InputStream in = proc.getInputStream();
                    FileOutputStream out = new FileOutputStream(logFile, true);
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                        out.flush();
                    }
                    out.close();
                } catch (IOException ignored) {
                }
            }
        }, "applog-writer").start();
    }

    /** 当前活动网络的 DNS 服务器列表（逗号分隔的 IP）；任何一步拿不到就返回 null。 */
    private String systemDnsServers() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return null;
            Network net = cm.getActiveNetwork();
            if (net == null) return null;
            LinkProperties lp = cm.getLinkProperties(net);
            if (lp == null) return null;
            List<InetAddress> servers = lp.getDnsServers();
            if (servers == null || servers.isEmpty()) return null;
            StringBuilder sb = new StringBuilder();
            for (InetAddress a : servers) {
                String h = a.getHostAddress();
                if (h == null || h.isEmpty()) continue;
                if (sb.length() > 0) sb.append(',');
                sb.append(h);
            }
            return sb.length() == 0 ? null : sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void appendLog(String msg) {
        try {
            File f = new File(getFilesDir(), "applog.txt");
            FileOutputStream out = new FileOutputStream(f, true);
            String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
            out.write(("[" + ts + "] " + msg + "\n").getBytes("UTF-8"));
            out.close();
        } catch (Exception ignored) {
        }
    }

    // ---------------- 前台通知 ----------------

    private void createChannel() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "节点服务", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("免费公益节点面板在手机本机运行的节点服务");
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }

    private Notification buildNotification() {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle("免费公益节点面板")
                .setContentText("节点服务运行中 · 点按打开面板")
                .setOngoing(true)
                .setContentIntent(pi)
                .build();
    }
}
