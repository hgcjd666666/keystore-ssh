package com.dsh.keystore;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** 从 OpenSSH 私钥 PEM 里取出 Ed25519 的 32 字节 seed / 公钥 blob */
public final class OpenSshKey {

    private static final byte[] MAGIC = "openssh-key-v1\u0000".getBytes(StandardCharsets.US_ASCII);

    private OpenSshKey() {}

    private static byte[] decodePem(String pem) {
        StringBuilder b64 = new StringBuilder();
        for (String line : pem.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("-----")) continue;
            b64.append(t);
        }
        return Base64.getDecoder().decode(b64.toString());
    }

    private static SshAgentProtocol.Reader open(String pem) {
        byte[] raw = decodePem(pem);
        if (raw.length < MAGIC.length) throw new IllegalArgumentException("key too short");
        for (int i = 0; i < MAGIC.length; i++) {
            if (raw[i] != MAGIC[i]) throw new IllegalArgumentException("not openssh-key-v1");
        }
        return new SshAgentProtocol.Reader(raw, MAGIC.length);
    }

    /** 32 字节 Ed25519 seed（BouncyCastle 用它签名） */
    public static byte[] parseEd25519Seed(String pem) throws Exception {
        SshAgentProtocol.Reader r = open(pem);
        String cipher = new String(r.string(), StandardCharsets.US_ASCII);
        String kdf = new String(r.string(), StandardCharsets.US_ASCII);
        r.string();                          // kdfoptions
        long nkeys = r.u32();
        if (!"none".equals(cipher) || !"none".equals(kdf)) {
            throw new IllegalArgumentException("encrypted key not supported: cipher=" + cipher);
        }
        if (nkeys != 1) throw new IllegalArgumentException("nkeys=" + nkeys);
        r.string();                          // public blob
        byte[] priv = r.string();            // private section

        SshAgentProtocol.Reader pr = new SshAgentProtocol.Reader(priv, 0);
        pr.u32();                            // checkint1
        pr.u32();                            // checkint2
        String keyType = new String(pr.string(), StandardCharsets.US_ASCII);
        if (!SshAgentProtocol.ED25519.equals(keyType)) {
            throw new IllegalArgumentException("not ed25519: " + keyType);
        }
        pr.string();                         // pub 32B
        byte[] priv64 = pr.string();         // seed(32) || pub(32)
        if (priv64.length != 64) throw new IllegalArgumentException("bad ed25519 priv len " + priv64.length);
        byte[] seed = new byte[32];
        System.arraycopy(priv64, 0, seed, 0, 32);
        return seed;
    }

    /** 公钥 blob（ssh-ed25519 | pub32），用来和 agent 请求里的 key blob 比对 */
    public static byte[] parsePublicBlob(String pem) throws Exception {
        SshAgentProtocol.Reader r = open(pem);
        r.string();  // cipher
        r.string();  // kdf
        r.string();  // kdfopts
        r.u32();     // nkeys
        return r.string();
    }

    /**
     * 私钥里附带的 comment（authorized_keys 里公钥行末尾那段）。
     * OpenSSH 把它放在私有段：checkint1 | checkint2 | keytype | pub | priv | comment。
     * 拿不到就返回空串，不影响导入。
     */
    public static String parseComment(String pem) {
        try {
            SshAgentProtocol.Reader r = open(pem);
            r.string();  // cipher
            r.string();  // kdf
            r.string();  // kdfopts
            r.u32();     // nkeys
            r.string();  // public blob
            byte[] priv = r.string();

            SshAgentProtocol.Reader pr = new SshAgentProtocol.Reader(priv, 0);
            pr.u32();    // checkint1
            pr.u32();    // checkint2
            String keyType = new String(pr.string(), StandardCharsets.US_ASCII);
            pr.string();                 // pub
            if (SshAgentProtocol.ED25519.equals(keyType)) {
                pr.string();             // 64B seed+pub
            } else if (keyType.startsWith("ecdsa-sha2-")) {
                pr.string();             // curve name
                pr.string();             // Q
                pr.string();             // d
            } else {
                return "";
            }
            return new String(pr.string(), StandardCharsets.UTF_8).trim();
        } catch (Throwable t) {
            return "";
        }
    }
}
