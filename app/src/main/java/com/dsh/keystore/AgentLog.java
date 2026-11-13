package com.dsh.keystore;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

/**
 * 进程内环形日志，供 UI 的日志页展示。
 * 只保留最近 MAX 条，UI 轮询 snapshot() 即可，不需要回调。
 */
public final class AgentLog {

    private static final int MAX = 800;
    private static final LinkedList<String> LINES = new LinkedList<>();
    private static final Object LOCK = new Object();
    private static final SimpleDateFormat FMT = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private AgentLog() {}

    public static void add(String tag, String msg) {
        String line = FMT.format(new Date()) + "  [" + tag + "] " + msg;
        synchronized (LOCK) {
            LINES.addLast(line);
            while (LINES.size() > MAX) LINES.removeFirst();
        }
        Log.i(tag, msg);
    }

    public static List<String> snapshot() {
        synchronized (LOCK) {
            return new ArrayList<>(LINES);
        }
    }

    public static void clear() {
        synchronized (LOCK) {
            LINES.clear();
        }
    }
}
