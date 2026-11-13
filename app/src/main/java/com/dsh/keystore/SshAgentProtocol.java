package com.dsh.keystore;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * ssh-agent 协议的最小实现（Ed25519，多把 key）。
 *
 * 报文：uint32 length | byte type | payload
 *   11 SSH2_AGENTC_REQUEST_IDENTITIES -> 12 SSH2_AGENT_IDENTITIES_ANSWER（n 条 blob+comment）
 *   13 SSH2_AGENTC_SIGN_REQUEST       -> 14 SSH2_AGENT_SIGN_RESPONSE
 *   失败回 5 SSH_AGENT_FAILURE
 *
 * 选钥匙的方式：SIGN_REQUEST 里带着公钥 blob，用它反查库里的私钥条目。
 * 请求方指名的是公钥，私钥始终留在 Keystore 里。
 */
public final class SshAgentProtocol {

    public static final int SSH_AGENT_FAILURE = 5;
    public static final int SSH_AGENT_SUCCESS = 6;
    public static final int SSH2_AGENTC_REQUEST_IDENTITIES = 11;
    public static final int SSH2_AGENT_IDENTITIES_ANSWER = 12;
    public static final int SSH2_AGENTC_SIGN_REQUEST = 13;
    public static final int SSH2_AGENT_SIGN_RESPONSE = 14;

    public static final String ED25519 = "ssh-ed25519";
    public static final String HOSTBOUND = "publickey-hostbound-v00@openssh.com";

    private SshAgentProtocol() {}

    // ---------------------------------------------------------------- 读写

    public static byte[] readPacket(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len <= 0 || len > (1 << 20)) throw new IOException("bad packet length " + len);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    public static void writePacket(DataOutputStream out, byte[] typeAndPayload) throws IOException {
        out.writeInt(typeAndPayload.length);
        out.write(typeAndPayload);
        out.flush();
    }

    private static byte[] op(int type) {
        return new byte[]{(byte) type};
    }

    // ---------------------------------------------------------------- 消息构造

    /**
     * 多把钥匙的身份应答。
     * comments 为空或长度不匹配时按空串填充，协议上 comment 只用于展示。
     */
    public static byte[] identitiesAnswer(java.util.List<byte[]> pubBlobs, java.util.List<String> comments) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(SSH2_AGENT_IDENTITIES_ANSWER);
        u32(b, pubBlobs.size());
        for (int i = 0; i < pubBlobs.size(); i++) {
            writeAll(b, string(pubBlobs.get(i)));
            String c = (comments != null && i < comments.size()) ? comments.get(i) : "";
            writeAll(b, string(c == null ? "" : c));
        }
        return b.toByteArray();
    }

    public static byte[] identitiesAnswerEmpty() {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(SSH2_AGENT_IDENTITIES_ANSWER);
        u32(b, 0);
        return b.toByteArray();
    }

    public static byte[] signResponse(byte[] signature) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(SSH2_AGENT_SIGN_RESPONSE);
        writeAll(b, string(signature));
        return b.toByteArray();
    }

    public static byte[] failure() {
        return op(SSH_AGENT_FAILURE);
    }

    // ---------------------------------------------------------------- 解析

    public static final class SignRequest {
        public byte[] keyBlob;
        public byte[] data;
        public long flags;
        public String keyType;
    }

    public static SignRequest parseSignRequest(byte[] packet) throws IOException {
        Reader r = new Reader(packet, 1);   // 跳过 type 字节
        SignRequest s = new SignRequest();
        s.keyBlob = r.string();
        s.data = r.string();
        s.flags = r.u32();
        s.keyType = keyTypeOf(s.keyBlob);
        return s;
    }

    /** 从 key blob 里取算法名（第一个 string） */
    public static String keyTypeOf(byte[] keyBlob) {
        try {
            Reader r = new Reader(keyBlob, 0);
            return new String(r.string(), StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return "";
        }
    }

    /** 把公钥 blob 的算法名换回标准 ssh-ed25519（用于比对） */
    public static byte[] normalizeKeyBlob(byte[] keyBlob) {
        String t = keyTypeOf(keyBlob);
        if (!t.equals(HOSTBOUND)) return keyBlob;
        Reader r = new Reader(keyBlob, 0);
        try {
            r.string();                       // 丢掉原算法名
            byte[] rest = r.remaining();
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            writeAll(b, string(ED25519.getBytes(StandardCharsets.US_ASCII)));
            writeAll(b, rest);
            return b.toByteArray();
        } catch (Exception e) {
            return keyBlob;
        }
    }

    /** 用 Ed25519 seed 对 data 签名，返回 agent 的签名 blob */
    public static byte[] ed25519Signature(byte[] seed32, byte[] data, String keyTypeForName) throws Exception {
        org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters priv =
                new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed32, 0);
        org.bouncycastle.crypto.signers.Ed25519Signer signer =
                new org.bouncycastle.crypto.signers.Ed25519Signer();
        signer.init(true, priv);
        signer.update(data, 0, data.length);
        byte[] raw = signer.generateSignature();      // 64 字节
        if (raw.length != 64) throw new IllegalStateException("bad ed25519 signature length " + raw.length);

        String name = (keyTypeForName != null && keyTypeForName.length() > 0)
                ? keyTypeForName : ED25519;
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        writeAll(b, string(name.getBytes(StandardCharsets.US_ASCII)));
        writeAll(b, string(raw));
        return b.toByteArray();
    }

    // ---------------------------------------------------------------- 编码工具

    private static void writeAll(ByteArrayOutputStream b, byte[] v) {
        b.write(v, 0, v.length);
    }

    public static byte[] string(byte[] v) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        u32(b, v.length);
        b.write(v, 0, v.length);
        return b.toByteArray();
    }

    public static byte[] string(String v) {
        return string(v.getBytes(StandardCharsets.UTF_8));
    }

    public static void u32(ByteArrayOutputStream b, int v) {
        b.write((v >>> 24) & 0xff);
        b.write((v >>> 16) & 0xff);
        b.write((v >>> 8) & 0xff);
        b.write(v & 0xff);
    }

    /** 极简 SSH 二进制读者 */
    public static final class Reader {
        private final byte[] buf;
        private int pos;

        public Reader(byte[] buf, int start) {
            this.buf = buf;
            this.pos = start;
        }

        public int u8() throws EOFException {
            if (pos + 1 > buf.length) throw new EOFException();
            return buf[pos++] & 0xff;
        }

        public long u32() throws EOFException {
            if (pos + 4 > buf.length) throw new EOFException();
            long v = ((long) (buf[pos] & 0xff) << 24)
                    | ((long) (buf[pos + 1] & 0xff) << 16)
                    | ((long) (buf[pos + 2] & 0xff) << 8)
                    | (buf[pos + 3] & 0xff);
            pos += 4;
            return v;
        }

        public byte[] string() throws EOFException {
            int len = (int) u32();
            if (len < 0 || pos + len > buf.length) throw new EOFException();
            byte[] out = new byte[len];
            System.arraycopy(buf, pos, out, 0, len);
            pos += len;
            return out;
        }

        public byte[] remaining() {
            byte[] out = new byte[buf.length - pos];
            System.arraycopy(buf, pos, out, 0, out.length);
            pos = buf.length;
            return out;
        }
    }
}
