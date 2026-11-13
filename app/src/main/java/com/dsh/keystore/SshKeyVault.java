package com.dsh.keystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 多密钥保险箱：Keystore KEK（AES-256-GCM，TEE 内不可导出）保护每一把 SSH 私钥。
 *
 *   KEK = AES-256-GCM，材料在 TEE/StrongBox 里，永不导出；
 *         setUserAuthenticationRequired(true) + per-use：
 *         每次解封私钥都必须现场指纹，Keystore 硬件校验，App 无法绕过。
 *
 *   每条记录 = { id, comment, pubLine, pubBlob, iv, ct }
 *     comment  = 公钥行末尾那段（如 "dsh"），用于让请求方指名要哪把钥匙
 *     pubLine  = "ssh-ed25519 AAAA... dsh"
 *     ct       = AES-GCM(OpenSSH 私钥明文)，只有指纹通过后才能解出来
 *
 * 设计原则：私钥只进不出。本类不提供任何"导出明文/复制到剪贴板"的入口，
 *          解封只发生在签名瞬间，用完立即在调用方清零。
 */
public final class SshKeyVault {

    private static final String KEK_ALIAS = "ssh_kek_aes256";
    private static final String LEGACY_ALIAS = "ssh_dek_wrap_rsa";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final String PREF = "ssh_vault";
    private static final String KEY_ENTRIES = "key_entries";
    private static final String LEGACY_BLOB = "sealed_blob";
    private static final String LEGACY_PUB = "pub_line";
    private static final String LEGACY_PUB_BLOB = "pub_blob";
    private static final int VERSION = 2;

    private SshKeyVault() {}

    // ------------------------------------------------------------ 一条密钥

    public static final class Entry {
        public String id;
        public String comment;
        public String pubLine;
        public String pubBlobB64;
        public Sealed sealed;

        /** 公钥 blob 原始字节（agent 协议里就是这串） */
        public byte[] pubBlob() {
            return unb64(pubBlobB64);
        }

        /** 形如 SHA256:xxxx 的指纹，仅用于界面展示，不参与匹配 */
        public String fingerprint() {
            try {
                byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(pubBlob());
                return "SHA256:" + Base64.encodeToString(d, Base64.NO_WRAP | Base64.NO_PADDING)
                        .replace('+', '-').replace('/', '_');
            } catch (Throwable t) {
                return "?";
            }
        }

        public String label() {
            return (comment == null || comment.isEmpty()) ? id : comment;
        }
    }

    // ------------------------------------------------------------ 密文本体

    public static final class Sealed {
        public final byte[] iv;
        public final byte[] ciphertext;

        public Sealed(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        public int totalBytes() {
            return iv.length + ciphertext.length;
        }
    }

    // ------------------------------------------------------------ KEK

    public static final class KekInfo {
        public boolean created;
        public long generateMs;
        public String securityLevel = "?";
        public boolean insideSecureHardware;
        public boolean strongBoxBacked;
        public boolean userAuthRequired;
        public int authDurationSeconds = -999;
        public int authType = -1;
        public boolean authEnforcedByHw;
        public String algorithm = "?";
        public int keySize = -1;

        public String describe() {
            return algorithm + " " + keySize + "bit | level=" + securityLevel
                    + " | hw=" + insideSecureHardware + " | strongbox=" + strongBoxBacked
                    + " | authRequired=" + userAuthRequired
                    + " | authDur=" + authDurationSeconds
                    + " | authType=0x" + Integer.toHexString(authType)
                    + " | authHwEnforced=" + authEnforcedByHw
                    + " | " + (created ? "新生成" : "复用") + " | gen=" + generateMs + "ms";
        }
    }

    public static boolean kekExists() throws Exception {
        return store().containsAlias(KEK_ALIAS);
    }

    public static KekInfo ensureKek(boolean preferStrongBox, boolean requireAuth) throws Exception {
        long t0 = System.nanoTime();
        KeyStore ks = store();
        KekInfo info = new KekInfo();
        info.created = false;

        if (!ks.containsAlias(KEK_ALIAS)) {
            boolean ok = false;
            if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    generate(true, requireAuth);
                    ok = true;
                } catch (Throwable ignored) {
                    ok = false;
                }
            }
            if (!ok) generate(false, requireAuth);
            info.created = true;
            ks = store();
        }
        info.generateMs = (System.nanoTime() - t0) / 1_000_000L;

        SecretKey kek = (SecretKey) ks.getKey(KEK_ALIAS, null);
        if (kek != null) {
            KeyInfo ki = (KeyInfo) javax.crypto.SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
                    .getKeySpec(kek, KeyInfo.class);
            info.insideSecureHardware = ki.isInsideSecureHardware();
            info.userAuthRequired = ki.isUserAuthenticationRequired();
            info.authDurationSeconds = ki.getUserAuthenticationValidityDurationSeconds();
            info.authType = ki.getUserAuthenticationType();
            info.authEnforcedByHw = ki.isUserAuthenticationRequirementEnforcedBySecureHardware();
            Boolean sb = reflectBool(ki, "isStrongBoxBacked");
            info.strongBoxBacked = sb != null && sb;
            info.securityLevel = securityLevel(ki);
            info.algorithm = kek.getAlgorithm();
            info.keySize = ki.getKeySize();
        }
        return info;
    }

    private static void generate(boolean strongBox, boolean requireAuth) throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore");
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                KEK_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true);

        if (requireAuth) {
            // per-use（-1）：不产生授权缓存，每次使用都必须现场认证。API 23+ 可用。
            b.setUserAuthenticationRequired(true);
            b.setUserAuthenticationValidityDurationSeconds(-1);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
            }
            b.setInvalidatedByBiometricEnrollment(true);
        } else {
            b.setUserAuthenticationRequired(false);
        }

        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            b.setIsStrongBoxBacked(true);
        }
        kg.init(b.build());
        kg.generateKey();
    }

    private static Boolean reflectBool(Object o, String m) {
        try {
            return (Boolean) o.getClass().getMethod(m).invoke(o);
        } catch (Throwable t) {
            return null;
        }
    }

    private static Integer reflectInt(Object o, String m) {
        try {
            return (Integer) o.getClass().getMethod(m).invoke(o);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String securityLevel(KeyInfo ki) {
        Integer lvl = reflectInt(ki, "getSecurityLevel");   // SOFTWARE=0 TEE=1 STRONGBOX=2
        if (lvl == null) return ki.isInsideSecureHardware() ? "TEE(hw)" : "SOFTWARE";
        switch (lvl) {
            case 2: return "STRONGBOX";
            case 1: return "TEE";
            case 0: return "SOFTWARE";
            default: return "UNKNOWN(" + lvl + ")";
        }
    }

    private static KeyStore store() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    public static void deleteAllKeys() throws Exception {
        KeyStore ks = store();
        if (ks.containsAlias(KEK_ALIAS)) ks.deleteEntry(KEK_ALIAS);
        if (ks.containsAlias(LEGACY_ALIAS)) ks.deleteEntry(LEGACY_ALIAS);
    }

    // ------------------------------------------------------------ 加密 / 解密（可要求指纹）

    public static final class Prepared {
        public final Cipher cipher;
        public final boolean alreadyAuthorized;
        public final byte[] iv;

        Prepared(Cipher c, boolean auth, byte[] iv) {
            cipher = c;
            alreadyAuthorized = auth;
            this.iv = iv;
        }
    }

    /**
     * 准备加密 Cipher。KEK 绑定认证时 init 会抛 UserNotAuthenticatedException，
     * 该 Cipher 已持有 keystore 句柄，交给 BiometricPrompt.CryptoObject，
     * 认证通过后即可 doFinal（授权在框架/TEE 内完成，App 拿不到密钥）。
     */
    public static Prepared prepareSeal() throws Exception {
        SecretKey kek = (SecretKey) store().getKey(KEK_ALIAS, null);
        if (kek == null) throw new IllegalStateException("KEK 不存在");
        boolean needAuth = needsAuth(kek);
        Cipher c = Cipher.getInstance(TRANSFORM);
        try {
            // randomizedEncryptionRequired 的 Keystore 密钥禁止调用方自带 IV
            c.init(Cipher.ENCRYPT_MODE, kek);
        } catch (android.security.keystore.UserNotAuthenticatedException e) {
            // 统一交给 CryptoObject 流程
        }
        return new Prepared(c, !needAuth, null);
    }

    public static Sealed seal(Cipher cipher, byte[] plain) throws Exception {
        byte[] ct = cipher.doFinal(plain);
        return new Sealed(cipher.getIV(), ct);
    }

    public static Prepared prepareOpen(Sealed s) throws Exception {
        SecretKey kek = (SecretKey) store().getKey(KEK_ALIAS, null);
        if (kek == null) throw new IllegalStateException("KEK 不存在，无法解封");
        boolean needAuth = needsAuth(kek);
        Cipher c = Cipher.getInstance(TRANSFORM);
        try {
            c.init(Cipher.DECRYPT_MODE, kek, new GCMParameterSpec(128, s.iv));
        } catch (android.security.keystore.UserNotAuthenticatedException e) {
            // 同上：交给 CryptoObject 认证流程
        } catch (KeyPermanentlyInvalidatedException e) {
            throw e;
        }
        return new Prepared(c, !needAuth, s.iv);
    }

    public static boolean needsAuth(SecretKey kek) {
        try {
            KeyInfo ki = (KeyInfo) javax.crypto.SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
                    .getKeySpec(kek, KeyInfo.class);
            return ki.isUserAuthenticationRequired();
        } catch (Throwable t) {
            return true;   // 判断不了就按需要认证处理
        }
    }

    public static byte[] open(Cipher cipher, Sealed s) throws Exception {
        return cipher.doFinal(s.ciphertext);
    }

    // ------------------------------------------------------------ 多密钥持久化

    public static List<Entry> listEntries(Context ctx) {
        List<Entry> out = new ArrayList<>();
        String raw = prefs(ctx).getString(KEY_ENTRIES, null);
        if (raw == null) {
            Entry migrated = migrateLegacy(ctx);
            if (migrated != null) out.add(migrated);
            return out;
        }
        try {
            JSONArray arr = new JSONArray(raw);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                Entry e = new Entry();
                e.id = o.getString("id");
                e.comment = o.optString("comment", "");
                e.pubLine = o.getString("pubLine");
                e.pubBlobB64 = o.getString("pubBlob");
                e.sealed = new Sealed(unb64(o.getString("iv")), unb64(o.getString("ct")));
                out.add(e);
            }
        } catch (Throwable t) {
            // 数据损坏时不静默清空，返回空表让上层提示
        }
        return out;
    }

    public static void addEntry(Context ctx, String comment, String pubLine, byte[] pubBlob, Sealed sealed) {
        List<Entry> list = listEntries(ctx);
        Entry e = new Entry();
        e.id = newId();
        e.comment = comment == null ? "" : comment;
        e.pubLine = pubLine;
        e.pubBlobB64 = b64(pubBlob);
        e.sealed = sealed;
        list.add(e);
        saveAll(ctx, list);
    }

    public static void removeEntry(Context ctx, String id) {
        List<Entry> list = listEntries(ctx);
        List<Entry> keep = new ArrayList<>();
        for (Entry e : list) if (!e.id.equals(id)) keep.add(e);
        saveAll(ctx, keep);
    }

    /** 按公钥 blob 精确查找（agent 收到 SIGN_REQUEST 时用） */
    public static Entry findByBlob(Context ctx, byte[] blob) {
        String want = b64(blob);
        for (Entry e : listEntries(ctx)) {
            if (e.pubBlobB64.equals(want)) return e;
        }
        return null;
    }

    /** 按 comment 查找（PC 端指名要哪把钥匙 / 界面选择时用） */
    public static Entry findByComment(Context ctx, String comment) {
        if (comment == null) return null;
        for (Entry e : listEntries(ctx)) {
            if (comment.equals(e.comment)) return e;
        }
        return null;
    }

    public static boolean isEmpty(Context ctx) {
        return listEntries(ctx).isEmpty();
    }

    /**
     * 把公钥列表写成 filesDir/pubkeys.json，供 root 侧 agent 做 identities 应答。
     * 只有公钥（本来就是公开信息），不含任何私钥材料。
     */
    public static void writePublicIndex(Context ctx) {
        try {
            JSONArray arr = new JSONArray();
            for (Entry e : listEntries(ctx)) {
                JSONObject o = new JSONObject();
                o.put("comment", e.comment == null ? "" : e.comment);
                o.put("pub", e.pubBlobB64);
                arr.put(o);
            }
            java.io.File f = new java.io.File(ctx.getFilesDir(), "pubkeys.json");
            java.io.FileWriter w = new java.io.FileWriter(f, false);
            try {
                w.write(arr.toString());
            } finally {
                w.close();
            }
            f.setReadable(true, false);   // root agent 要读
        } catch (Throwable t) {
            android.util.Log.w("SshKeyVault", "writePublicIndex failed: " + t);
        }
    }

    private static void saveAll(Context ctx, List<Entry> list) {
        try {
            JSONArray arr = new JSONArray();
            for (Entry e : list) {
                JSONObject o = new JSONObject();
                o.put("id", e.id);
                o.put("comment", e.comment);
                o.put("pubLine", e.pubLine);
                o.put("pubBlob", e.pubBlobB64);
                o.put("iv", b64(e.sealed.iv));
                o.put("ct", b64(e.sealed.ciphertext));
                arr.put(o);
            }
            prefs(ctx).edit().putString(KEY_ENTRIES, arr.toString()).apply();
        } catch (Throwable t) {
            throw new IllegalStateException("保存密钥元数据失败: " + t);
        }
    }

    /** 旧版单密钥（sealed_blob + pub_line）迁移成一条记录 */
    private static Entry migrateLegacy(Context ctx) {
        String blob = prefs(ctx).getString(LEGACY_BLOB, null);
        if (blob == null) return null;
        String pubLine = prefs(ctx).getString(LEGACY_PUB, "");
        String pubBlobB64 = prefs(ctx).getString(LEGACY_PUB_BLOB, "");
        if (pubLine.isEmpty() || pubBlobB64.isEmpty()) return null;
        try {
            String[] p = blob.split("\n");
            if (p.length != 3) return null;
            Entry e = new Entry();
            e.id = newId();
            e.comment = commentOf(pubLine);
            e.pubLine = pubLine;
            e.pubBlobB64 = pubBlobB64;
            e.sealed = new Sealed(unb64(p[1]), unb64(p[2]));
            List<Entry> list = new ArrayList<>();
            list.add(e);
            saveAll(ctx, list);
            prefs(ctx).edit().remove(LEGACY_BLOB).remove(LEGACY_PUB).remove(LEGACY_PUB_BLOB).apply();
            return e;
        } catch (Throwable t) {
            return null;
        }
    }

    public static void clearAll(Context ctx) {
        prefs(ctx).edit().remove(KEY_ENTRIES)
                .remove(LEGACY_BLOB).remove(LEGACY_PUB).remove(LEGACY_PUB_BLOB).apply();
    }

    public static String commentOf(String pubLine) {
        if (pubLine == null) return "";
        String[] parts = pubLine.trim().split("\\s+");
        return parts.length >= 3 ? parts[2] : "";
    }

    private static String newId() {
        byte[] r = new byte[8];
        new SecureRandom().nextBytes(r);
        StringBuilder sb = new StringBuilder();
        for (byte b : r) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    // ------------------------------------------------------------ 工具

    public static List<String> aliases() throws Exception {
        KeyStore ks = store();
        Enumeration<String> e = ks.aliases();
        List<String> out = new ArrayList<>();
        while (e.hasMoreElements()) out.add(e.nextElement());
        Collections.sort(out);
        return out;
    }

    public static String sha256Hex(byte[] data) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(data);
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String b64(byte[] b) {
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }

    public static byte[] unb64(String s) {
        return Base64.decode(s, Base64.NO_WRAP);
    }
}
