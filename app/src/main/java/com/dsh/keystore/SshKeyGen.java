package com.dsh.keystore;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EdECPoint;
import java.util.Base64;

/**
 * 生成 SSH 密钥对，编码成 OpenSSH 标准格式（ssh 客户端可直接用）。
 * 纯 JDK 实现，无 Android 依赖，桌面上可独立验证。
 *
 *   优先 Ed25519（现代默认推荐：短、快、无曲线参数陷阱）；
 *   运行环境不支持时自动回退 ECDSA P-256。
 */
public final class SshKeyGen {

    public static final class Result {
        public final String algo;         // Ed25519 / ECDSA-P256
        public final String privatePem;
        public final String publicLine;
        public final String fingerprintHex;

        Result(String algo, String priv, String pub, String fp) {
            this.algo = algo;
            privatePem = priv;
            publicLine = pub;
            fingerprintHex = fp;
        }
    }

    private SshKeyGen() {}

    /** 优先 ed25519，失败回退 ecdsa */
    public static Result generate(String comment, SecureRandom rnd) throws Exception {
        try {
            return ed25519(comment, rnd);
        } catch (Throwable t) {
            return ecdsa(comment, rnd);
        }
    }

    // ---------------------------------------------------------------- Ed25519

    static Result ed25519(String comment, SecureRandom rnd) throws Exception {
        // 用 BouncyCastle 的低层 API：直接拿 32 字节 seed 和 32 字节压缩公钥，
        // 不经过 JCA provider（Android 的 Conscrypt 不保证有 Ed25519 KeyPairGenerator）。
        org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters priv =
                new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(rnd);
        byte[] seed = priv.getEncoded();
        byte[] pub = priv.generatePublicKey().getEncoded();

        byte[] priv64 = new byte[64];                           // openssh 的 ed25519 私钥 = seed||pub
        System.arraycopy(seed, 0, priv64, 0, 32);
        System.arraycopy(pub, 0, priv64, 32, 32);

        ByteArrayOutputStream pkBlob = new ByteArrayOutputStream();
        write(pkBlob, "ssh-ed25519");
        write(pkBlob, pub);
        byte[] pubBlob = pkBlob.toByteArray();

        ByteArrayOutputStream sec = new ByteArrayOutputStream();
        int check = rnd.nextInt();
        u32(sec, check);
        u32(sec, check);
        write(sec, "ssh-ed25519");
        write(sec, pub);
        write(sec, priv64);
        write(sec, comment == null ? "" : comment);
        pad8(sec);

        return pkg("Ed25519", pubBlob, sec.toByteArray(), "ssh-ed25519", comment);
    }

    /** Ed25519 公钥点 -> RFC 8032 压缩编码：y 的 little-endian 32 字节，最高位置 x 的奇偶 */
    static byte[] encodeEdPoint(EdECPoint p) {
        byte[] out = new byte[32];
        byte[] y = p.getY().toByteArray();          // big-endian, 可能带符号字节
        for (int i = 0; i < 32; i++) {
            int idx = y.length - 1 - i;
            out[i] = idx >= 0 ? y[idx] : 0;
        }
        if (p.isXOdd()) out[31] |= (byte) 0x80;
        return out;
    }

    // ---------------------------------------------------------------- ECDSA P-256

    static Result ecdsa(String comment, SecureRandom rnd) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), rnd);
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();

        byte[] q = new byte[65];                     // 04 || X || Y
        q[0] = 0x04;
        System.arraycopy(fixed(pubKey.getW().getAffineX(), 32), 0, q, 1, 32);
        System.arraycopy(fixed(pubKey.getW().getAffineY(), 32), 0, q, 33, 32);
        byte[] d = fixed(privKey.getS(), 32);

        ByteArrayOutputStream pkBlob = new ByteArrayOutputStream();
        write(pkBlob, "ecdsa-sha2-nistp256");
        write(pkBlob, "nistp256");
        write(pkBlob, q);
        byte[] pubBlob = pkBlob.toByteArray();

        ByteArrayOutputStream sec = new ByteArrayOutputStream();
        int check = rnd.nextInt();
        u32(sec, check);
        u32(sec, check);
        write(sec, "ecdsa-sha2-nistp256");
        write(sec, "nistp256");
        write(sec, q);
        write(sec, d);
        write(sec, comment == null ? "" : comment);
        pad8(sec);

        return pkg("ECDSA-P256", pubBlob, sec.toByteArray(), "ecdsa-sha2-nistp256", comment);
    }

    // ---------------------------------------------------------------- 组装 openssh-key-v1

    private static Result pkg(String algo, byte[] pubBlob, byte[] privSection,
                              String keyType, String comment) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] magic = "openssh-key-v1\u0000".getBytes(StandardCharsets.US_ASCII);
        out.write(magic, 0, magic.length);
        write(out, "none");   // ciphername
        write(out, "none");   // kdfname
        write(out, "");       // kdfoptions
        u32(out, 1);          // nkeys
        write(out, pubBlob);
        write(out, privSection);

        String b64 = Base64.getEncoder().encodeToString(out.toByteArray());
        StringBuilder pem = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (int i = 0; i < b64.length(); i += 70) {
            pem.append(b64, i, Math.min(i + 70, b64.length())).append('\n');
        }
        pem.append("-----END OPENSSH PRIVATE KEY-----\n");

        String pub = keyType + " " + Base64.getEncoder().encodeToString(pubBlob)
                + (comment == null || comment.isEmpty() ? "" : " " + comment);

        return new Result(algo, pem.toString(), pub, sha256Hex(pubBlob));
    }

    static void pad8(ByteArrayOutputStream sec) {
        int padLen = 8 - (sec.size() % 8);
        for (int i = 1; i <= padLen; i++) sec.write(i);
    }

    static byte[] fixed(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) {
            System.arraycopy(b, b.length - len, out, 0, len);
        } else {
            System.arraycopy(b, 0, out, len - b.length, b.length);
        }
        return out;
    }

    static void u32(ByteArrayOutputStream o, int v) {
        o.write((v >>> 24) & 0xff);
        o.write((v >>> 16) & 0xff);
        o.write((v >>> 8) & 0xff);
        o.write(v & 0xff);
    }

    static void write(ByteArrayOutputStream o, byte[] b) {
        u32(o, b.length);
        o.write(b, 0, b.length);
    }

    static void write(ByteArrayOutputStream o, String s) {
        write(o, s.getBytes(StandardCharsets.UTF_8));
    }

    static String sha256Hex(byte[] d) {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(d);
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "?";
        }
    }

    // ---------------------------------------------------------------- 桌面自验证

    /** java -cp . com.dsh.keystore.SshKeyGen out_dir —— 用 ssh-keygen -y 校验编码 */
    public static void main(String[] args) throws Exception {
        Result r = generate("demo@keystore-test", new SecureRandom());
        if (args.length > 0) {
            java.nio.file.Path dir = java.nio.file.Paths.get(args[0]);
            java.nio.file.Files.write(dir.resolve("id_key"), r.privatePem.getBytes(StandardCharsets.UTF_8));
            java.nio.file.Files.write(dir.resolve("id_key.pub"),
                    (r.publicLine + "\n").getBytes(StandardCharsets.UTF_8));
        }
        System.out.println("ALGO " + r.algo);
        System.out.println(r.publicLine);
    }
}
