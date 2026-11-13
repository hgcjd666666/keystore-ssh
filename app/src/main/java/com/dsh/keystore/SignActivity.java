package com.dsh.keystore;

import android.app.Activity;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * 签名 Activity —— 由 root 侧的 agent 拉起。
 *
 * 数据全部走系统通道，不落盘：
 *   Intent extras 传入：
 *     key   公钥 blob 的 base64（用它在密钥库里找哪把钥匙）
 *     data  待签数据的 base64
 *     host  回传地址（默认 127.0.0.1）
 *     port  回传端口（root agent 那边临时监听的端口）
 *
 *   签名完成后连回 host:port，写一行：
 *     成功  OK <签名 blob 的 base64>
 *     失败  ERR <原因>
 *   然后 finish。
 *
 * 没有界面，指纹通过才签名；私钥在这条路径里只活到签名结束。
 */
public class SignActivity extends Activity {

    private boolean started;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (started) return;
        started = true;
        try {
            handle();
        } catch (Throwable t) {
            reply("ERR exception: " + t);
            finish();
        }
    }

    private void handle() throws Throwable {
        Intent i = getIntent();
        String keyB64 = i.getStringExtra("key");
        String dataB64 = i.getStringExtra("data");
        String hostRaw = i.getStringExtra("host");
        final String host = hostRaw == null ? "127.0.0.1" : hostRaw;
        final int port = i.getIntExtra("port", 0);

        if (keyB64 == null || dataB64 == null || port <= 0) {
            reply("ERR bad request (key/data/port missing)");
            finish();
            return;
        }

        byte[] pubBlob = Base64.getDecoder().decode(keyB64);
        byte[] data = Base64.getDecoder().decode(dataB64);
        SshKeyVault.Entry entry = SshKeyVault.findByBlob(this, pubBlob);
        if (entry == null) {
            reply("ERR no key for " + keyB64.substring(0, Math.min(16, keyB64.length())));
            finish();
            return;
        }
        AgentLog.add("Sign", "请求签名 key=" + entry.label() + " data=" + data.length + "B");

        SshKeyVault.Prepared p = SshKeyVault.prepareOpen(entry.sealed);
        if (p.alreadyAuthorized) {
            doSign(p.cipher, entry, data, host, port);
            return;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            reply("ERR API < 28 no BiometricPrompt");
            finish();
            return;
        }
        int can = canAuthenticate();
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            reply("ERR biometric unavailable: " + can);
            finish();
            return;
        }

        java.util.concurrent.Executor ex = getMainExecutor();

        // 请求方 IP 来自 TCP 连接的对端地址（agent 在 accept 时取的），PC 伪造不了
        String peer = getIntent().getStringExtra("peer");
        String desc = (peer != null && !peer.isEmpty())
                ? getString(R.string.sign_desc_peer, peer, entry.label())
                : getString(R.string.sign_description);

        BiometricPrompt prompt = new BiometricPrompt.Builder(this)
                .setTitle(getString(R.string.sign_title))
                .setSubtitle(getString(R.string.sign_subtitle))
                .setDescription(desc)
                .setNegativeButton(getString(R.string.sign_deny), ex, (d, w) -> {
                    reply("ERR user denied");
                    finish();
                })
                .build();

        prompt.authenticate(new BiometricPrompt.CryptoObject(p.cipher), new CancellationSignal(), ex,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        try {
                            doSign(result.getCryptoObject().getCipher(), entry, data, host, port);
                        } catch (Throwable t) {
                            reply("ERR sign failed: " + t);
                        }
                        finish();
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence msg) {
                        reply("ERR auth " + code + ": " + msg);
                        finish();
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        // 等用户重试
                    }
                });
    }

    private int canAuthenticate() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return BiometricManager.BIOMETRIC_SUCCESS;
        }
        BiometricManager bm = getSystemService(BiometricManager.class);
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                ? bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                : bm.canAuthenticate();
    }

    private void doSign(Cipher cipher, SshKeyVault.Entry entry, byte[] data, String host, int port) throws Throwable {
        byte[] pemBytes = SshKeyVault.open(cipher, entry.sealed);
        String pem = new String(pemBytes, StandardCharsets.UTF_8);
        byte[] seed = OpenSshKey.parseEd25519Seed(pem);
        try {
            byte[] sig = SshAgentProtocol.ed25519Signature(seed, data, "ssh-ed25519");
            reply("OK " + Base64.getEncoder().encodeToString(sig));
            AgentLog.add("Sign", "已签名 " + data.length + "B key=" + entry.label());
        } finally {
            java.util.Arrays.fill(seed, (byte) 0);
            java.util.Arrays.fill(pemBytes, (byte) 0);
        }
    }

    /** 把结果写回 root agent 的临时端口（网络操作不能在主线程，切后台，写完再 finish） */
    private void reply(String line) {
        final String l = line;
        Intent i = getIntent();
        String h = i == null ? null : i.getStringExtra("host");
        final String host = h == null ? "127.0.0.1" : h;
        final int port = i == null ? 0 : i.getIntExtra("port", 0);
        new Thread(() -> {
            sendReply(host, port, l);
            runOnUiThread(this::finish);
        }, "sign-reply").start();
    }

    private void sendReply(String host, int port, String line) {
        try {
            if (port <= 0) {
                AgentLog.add("Sign", "无回传端口，结果丢弃");
                return;
            }
            try (Socket s = new Socket(InetAddress.getByName(host), port)) {
                s.setSoTimeout(5000);
                OutputStream out = s.getOutputStream();
                out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (Throwable t) {
            AgentLog.add("Sign", "回传失败: " + t);
        }
    }
}
