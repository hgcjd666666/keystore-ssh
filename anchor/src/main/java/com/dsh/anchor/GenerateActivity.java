package com.dsh.anchor;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 生成器（A）：隐藏图标，只由主 App（B）通过 startActivityForResult 拉起。
 *
 * 一次性口令加密：
 *   KEK = HMAC-SHA256( PBKDF2(口令, salt), ANDROID_ID )
 *   blob = "SV1" | salt | iv | AES-GCM(私钥 PEM)
 *
 * 于是：
 *   - 卸载任意一方都不影响（blob 由用户/主 App 保管，密钥只由口令决定）
 *   - 恢复出厂后 ANDROID_ID 变化 => 即使知道口令也解不开（满足"格式化失效"）
 *   - 口令本身是秘密，ANDROID_ID 只做绑定，不承担保密
 */
public class GenerateActivity extends Activity {

    public static final String EXTRA_BLOB = "blob";
    public static final String EXTRA_PUB = "pub";
    public static final String EXTRA_ALGO = "algo";

    private EditText input;
    private TextView log;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);

        TextView tip = new TextView(this);
        tip.setPadding(pad, pad, pad, 0);
        tip.setText("生成器（无桌面图标，仅由主 App 拉起）\n设置一个备份口令，用于导出加密的 SSH 私钥。\n口令不会被保存，忘记口令 = 私钥丢失。");

        input = new EditText(this);
        input.setHint("备份口令（至少 8 位）");
        input.setSingleLine(true);
        input.setPadding(pad, pad, pad, pad);

        Button go = new Button(this);
        go.setText("生成密钥并加密导出");
        go.setOnClickListener(v -> generate());

        Button ksBtn = new Button(this);
        ksBtn.setText("Keystore 自查 / 生成 A 的测试 KEK");
        ksBtn.setOnClickListener(v -> {
            try {
                android.security.keystore.KeyGenParameterSpec.Builder b =
                        new android.security.keystore.KeyGenParameterSpec.Builder(
                                "a_test_kek", android.security.keystore.KeyProperties.PURPOSE_ENCRYPT
                                | android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setKeySize(256);
                javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore");
                kg.init(b.build());
                kg.generateKey();

                // 再生成一个绑定生物识别的 KEK，测试 B 能否对它走指纹流程
                android.security.keystore.KeyGenParameterSpec.Builder b2 =
                        new android.security.keystore.KeyGenParameterSpec.Builder(
                                "a_test_kek_auth", android.security.keystore.KeyProperties.PURPOSE_ENCRYPT
                                | android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setKeySize(256)
                                .setUserAuthenticationRequired(true)
                                .setUserAuthenticationParameters(0,
                                        android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG);
                javax.crypto.KeyGenerator kg2 = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore");
                kg2.init(b2.build());
                kg2.generateKey();
                log.setText("A 已生成 a_test_kek / a_test_kek_auth\n" + listAliases());
            } catch (Throwable t) {
                log.setText("生成失败: " + t + "\n" + listAliases());
            }
        });

        Button cancel = new Button(this);
        cancel.setText("取消");
        cancel.setOnClickListener(v -> {
            setResult(RESULT_CANCELED);
            finish();
        });

        log = new TextView(this);
        log.setTypeface(android.graphics.Typeface.MONOSPACE);
        log.setTextSize(10f);
        log.setTextIsSelectable(true);
        log.setPadding(pad, pad, pad, pad);

        ScrollView sv = new ScrollView(this);
        sv.addView(log, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        root.addView(tip);
        root.addView(input);
        root.addView(go);
        root.addView(ksBtn);
        root.addView(cancel);
        root.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
    }

    private String listAliases() {
        try {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            java.util.List<String> out = new java.util.ArrayList<>();
            java.util.Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) out.add(e.nextElement());
            java.util.Collections.sort(out);
            return "uid=" + android.os.Process.myUid() + "\naliases=" + out;
        } catch (Throwable t) {
            return "读别名失败: " + t;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (log != null && (log.getText() == null || log.getText().length() == 0)) {
            log.setText(listAliases());
        }
    }

    private void generate() {
        String pw = input.getText().toString();
        if (pw.length() < 8) {
            log.setText("口令至少 8 位");
            return;
        }
        try {
            SecureRandom rnd = new SecureRandom();

            // 1) Ed25519 密钥对（BouncyCastle 低层 API，OpenSSH 编码）
            org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters priv =
                    new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(rnd);
            byte[] seed = priv.getEncoded();
            byte[] pub = priv.generatePublicKey().getEncoded();
            String pem = opensshEd25519(seed, pub, "android@device", rnd);
            String pubLine = "ssh-ed25519 " + b64(ed25519PubBlob(pub)) + " android@device";

            // 2) 口令 + 设备绑定派生 KEK
            byte[] salt = new byte[16];
            rnd.nextBytes(salt);
            byte[] kek = deriveKek(pw, salt);
            byte[] iv = new byte[12];
            rnd.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, iv));
            byte[] ct = c.doFinal(pem.getBytes(StandardCharsets.UTF_8));
            String blob = "SV1\n" + b64(salt) + "\n" + b64(iv) + "\n" + b64(ct);

            log.setText("生成完成\n\n公钥:\n" + pubLine
                    + "\n\n加密备份串(含口令保护，可存任何地方):\n" + blob);

            Intent data = new Intent();
            data.putExtra(EXTRA_BLOB, blob);
            data.putExtra(EXTRA_PUB, pubLine);
            data.putExtra(EXTRA_ALGO, "Ed25519");
            setResult(RESULT_OK, data);
        } catch (Throwable t) {
            log.setText("失败: " + t + "\n" + android.util.Log.getStackTraceString(t));
        }
    }

    // ---------------- 口令 + 设备绑定 KDF ----------------

    private byte[] deriveKek(String password, byte[] salt) throws Exception {
        String androidId = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 200_000, 256);
        byte[] pbk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(pbk, "HmacSHA256"));
        mac.update(("android-id:" + androidId).getBytes(StandardCharsets.UTF_8));
        byte[] out = mac.doFinal();
        java.util.Arrays.fill(pbk, (byte) 0);
        return out;
    }

    // ---------------- OpenSSH ed25519 编码 ----------------

    private static byte[] ed25519PubBlob(byte[] pub32) throws Exception {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        write(o, "ssh-ed25519");
        write(o, pub32);
        return o.toByteArray();
    }

    private static String opensshEd25519(byte[] seed, byte[] pub32, String comment, SecureRandom rnd) throws Exception {
        java.io.ByteArrayOutputStream sec = new java.io.ByteArrayOutputStream();
        int check = rnd.nextInt();
        u32(sec, check);
        u32(sec, check);
        write(sec, "ssh-ed25519");
        write(sec, pub32);
        byte[] priv64 = new byte[64];
        System.arraycopy(seed, 0, priv64, 0, 32);
        System.arraycopy(pub32, 0, priv64, 32, 32);
        write(sec, priv64);
        write(sec, comment);
        int padLen = 8 - (sec.size() % 8);
        for (int i = 1; i <= padLen; i++) sec.write(i);

        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        byte[] magic = "openssh-key-v1\u0000".getBytes(StandardCharsets.US_ASCII);
        o.write(magic, 0, magic.length);
        write(o, "none");
        write(o, "none");
        write(o, "");
        u32(o, 1);
        write(o, ed25519PubBlob(pub32));
        write(o, sec.toByteArray());

        String b64 = b64(o.toByteArray());
        StringBuilder pem = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (int i = 0; i < b64.length(); i += 70) {
            pem.append(b64, i, Math.min(i + 70, b64.length())).append('\n');
        }
        pem.append("-----END OPENSSH PRIVATE KEY-----\n");
        return pem.toString();
    }

    private static void u32(java.io.ByteArrayOutputStream o, int v) {
        o.write((v >>> 24) & 0xff);
        o.write((v >>> 16) & 0xff);
        o.write((v >>> 8) & 0xff);
        o.write(v & 0xff);
    }

    private static void write(java.io.ByteArrayOutputStream o, byte[] b) {
        u32(o, b.length);
        o.write(b, 0, b.length);
    }

    private static void write(java.io.ByteArrayOutputStream o, String s) {
        write(o, s.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
