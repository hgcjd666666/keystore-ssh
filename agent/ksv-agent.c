// ksv-agent: root 侧 ssh-agent 网关（纯 C，不碰私钥）
//
// 职责：
//   · 监听 TCP 7022，跑 ssh-agent 协议
//   · REQUEST_IDENTITIES -> 读 app 写的 pubkeys.json（只有公钥）
//   · SIGN_REQUEST       -> am start 拉起 app 的 SignActivity，把待签数据放 Intent extras，
//                           签名结果由 app 通过本进程开的临时 socket 回传
//
// 私钥始终在 app 的 Keystore 里，本进程只转发协议。
//
// 编译：NDK clang -O2 -o ksv-agent ksv-agent.c
// 运行：su -c "nohup /data/local/tmp/ksv-agent >/data/local/tmp/ksv-agent.log 2>&1 &"
//
// 作为 Magisk 模块启动时（/data/adb/modules/<id>/bin/ksv-agent），会用 inotify
// 盯着模块目录：模块被卸载（目录消失）时立即自行退出，无需 uninstall.sh。

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <unistd.h>

#define LISTEN_PORT      7022
#define DISCOVERY_PORT   7023
#define DISCOVER_PROBE   "KSV_DISCOVER"
#define PREFS_PATH       "/data/data/com.dsh.keystore/shared_prefs/ssh_vault.xml"
#define PUBKEYS_PATH     "/data/data/com.dsh.keystore/files/pubkeys.json"
#define AM_PATH          "/system/bin/am"
#define SIGN_COMPONENT   "com.dsh.keystore/.SignActivity"
#define SIGN_TIMEOUT_MS  120000

#define SSH_AGENT_FAILURE             5
#define SSH_AGENT_SUCCESS             6
#define SSH_AGENTC_EXTENSION          27
#define SSH_AGENT_EXTENSION_FAILURE   28
#define SSH_AGENT_EXTENSION_RESPONSE  29
#define SSH2_AGENTC_REQUEST_IDENTITIES 11
#define SSH2_AGENT_IDENTITIES_ANSWER  12
#define SSH2_AGENTC_SIGN_REQUEST      13
#define SSH2_AGENT_SIGN_RESPONSE      14

// ---------------------------------------------------------------- 动态缓冲

typedef struct {
    unsigned char *p;
    size_t len;
    size_t cap;
} buf_t;

static void buf_init(buf_t *b) { b->p = NULL; b->len = 0; b->cap = 0; }

static void buf_reserve(buf_t *b, size_t need) {
    if (b->len + need <= b->cap) return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + need) cap *= 2;
    b->p = realloc(b->p, cap);
    if (!b->p) { perror("realloc"); exit(1); }
    b->cap = cap;
}

static void buf_put(buf_t *b, const void *data, size_t n) {
    buf_reserve(b, n);
    memcpy(b->p + b->len, data, n);
    b->len += n;
}

static void buf_u32(buf_t *b, unsigned v) {
    unsigned char x[4] = {(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff};
    buf_put(b, x, 4);
}

static void buf_string(buf_t *b, const void *data, size_t n) {
    buf_u32(b, (unsigned) n);
    buf_put(b, data, n);
}

// ---------------------------------------------------------------- base64

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const unsigned char *in, size_t n) {
    size_t out_len = 4 * ((n + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = B64[v & 63];
    }
    if (i < n) {
        unsigned v = in[i] << 16;
        int rem = (int) (n - i);
        if (rem == 2) v |= in[i + 1] << 8;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (rem == 2) ? B64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *b64_decode(const char *in, size_t *out_len) {
    size_t n = strlen(in), o = 0;
    unsigned char *out = malloc(n / 4 * 3 + 4);
    if (!out) return NULL;
    unsigned v = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=') break;
        int d = b64_val(in[i]);
        if (d < 0) continue;
        v = (v << 6) | (unsigned) d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char) ((v >> bits) & 0xff);
        }
    }
    *out_len = o;
    return out;
}

// ---------------------------------------------------------------- 读文件

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t) n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t) n, f);
    buf[got] = 0;
    fclose(f);
    return buf;
}

// ---------------------------------------------------------------- 公钥来源
// 主：app 的 shared_prefs（key_entries 里 pubBlob/comment 是明文 JSON）
// 备：app 主动导出的 pubkeys.json
//
// 私钥密文（iv/ct）就在同一个 JSON 里，但它由 TEE 里的 KEK 加密，
// 本进程既解不开也用不上；这里只取公钥。

typedef struct {
    char *comment;
    char *pub;      // base64 公钥 blob
} ksv_key_t;

static char *unescape_xml(const char *s, size_t n) {
    char *out = malloc(n + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '&') {
            if (i + 6 <= n && !strncmp(s + i, "&quot;", 6)) { out[o++] = '"'; i += 5; continue; }
            if (i + 5 <= n && !strncmp(s + i, "&amp;", 5)) { out[o++] = '&'; i += 4; continue; }
            if (i + 4 <= n && !strncmp(s + i, "&lt;", 4)) { out[o++] = '<'; i += 3; continue; }
            if (i + 4 <= n && !strncmp(s + i, "&gt;", 4)) { out[o++] = '>'; i += 3; continue; }
            if (i + 6 <= n && !strncmp(s + i, "&apos;", 6)) { out[o++] = '\''; i += 5; continue; }
        }
        out[o++] = s[i];
    }
    out[o] = 0;
    return out;
}

/** 从 shared_prefs XML 里取出 key_entries 的值（已反转义） */
static char *extract_prefs_entries(const char *xml) {
    const char *p = strstr(xml, "\"key_entries\"");
    if (!p) return NULL;
    p = strchr(p, '>');
    if (!p) return NULL;
    p++;
    const char *end = strstr(p, "</string>");
    if (!end) return NULL;
    return unescape_xml(p, (size_t) (end - p));
}

/** 解析 key_entries：[{"id":..,"comment":..,"pubLine":..,"pubBlob":..,"iv":..,"ct":..}] */
static int parse_entries_json(const char *json, ksv_key_t **out) {
    int cap = 16, n = 0;
    ksv_key_t *keys = calloc(cap, sizeof(ksv_key_t));
    if (!keys) return -1;
    const char *p = json;
    for (;;) {
        const char *cs = strstr(p, "\"comment\":\"");
        if (!cs) break;
        cs += strlen("\"comment\":\"");
        const char *ce = strchr(cs, '"');
        if (!ce) break;
        const char *ps = strstr(ce, "\"pubBlob\":\"");
        if (!ps) break;
        ps += strlen("\"pubBlob\":\"");
        const char *pe = strchr(ps, '"');
        if (!pe) break;
        if (n >= cap) { cap *= 2; keys = realloc(keys, cap * sizeof(ksv_key_t)); }
        keys[n].comment = strndup(cs, (size_t) (ce - cs));
        keys[n].pub = strndup(ps, (size_t) (pe - ps));
        n++;
        p = pe;
    }
    *out = keys;
    return n;
}

/** 解析 pubkeys.json：[{"comment":"dsh","pub":"AAA..."}] */
static int parse_pubkeys_json(const char *json, ksv_key_t **out) {
    int cap = 16, n = 0;
    ksv_key_t *keys = calloc(cap, sizeof(ksv_key_t));
    if (!keys) return -1;
    const char *p = json;
    for (;;) {
        const char *cs = strstr(p, "\"comment\":\"");
        if (!cs) break;
        cs += strlen("\"comment\":\"");
        const char *ce = strchr(cs, '"');
        if (!ce) break;
        const char *ps = strstr(ce, "\"pub\":\"");
        if (!ps) break;
        ps += strlen("\"pub\":\"");
        const char *pe = strchr(ps, '"');
        if (!pe) break;
        if (n >= cap) { cap *= 2; keys = realloc(keys, cap * sizeof(ksv_key_t)); }
        keys[n].comment = strndup(cs, (size_t) (ce - cs));
        keys[n].pub = strndup(ps, (size_t) (pe - ps));
        n++;
        p = pe;
    }
    *out = keys;
    return n;
}

static int load_pubkeys(ksv_key_t **out) {
    // 1) 直接读 app 的 shared_prefs（root 可读，公钥明文）
    char *xml = read_file(PREFS_PATH);
    if (xml) {
        char *json = extract_prefs_entries(xml);
        free(xml);
        if (json) {
            int n = parse_entries_json(json, out);
            free(json);
            if (n > 0) return n;
        }
    }
    // 2) 回退：pubkeys.json（app 导出的索引）
    char *j = read_file(PUBKEYS_PATH);
    if (!j) {
        *out = NULL;
        return 0;
    }
    int n = parse_pubkeys_json(j, out);
    free(j);
    return n;
}

// ---------------------------------------------------------------- 协议读写

static int read_packet(int fd, buf_t *out) {
    unsigned char hdr[4];
    if (read(fd, hdr, 4) != 4) return -1;
    unsigned len = ((unsigned) hdr[0] << 24) | ((unsigned) hdr[1] << 16)
                 | ((unsigned) hdr[2] << 8) | hdr[3];
    if (len == 0 || len > (1u << 20)) return -1;
    buf_init(out);
    buf_reserve(out, len);
    if (read(fd, out->p, len) != (ssize_t) len) return -1;
    out->len = len;
    return 0;
}

static int write_packet(int fd, const buf_t *b) {
    unsigned char hdr[4] = {(b->len >> 24) & 0xff, (b->len >> 16) & 0xff,
                            (b->len >> 8) & 0xff, b->len & 0xff};
    if (write(fd, hdr, 4) != 4) return -1;
    if (write(fd, b->p, b->len) != (ssize_t) b->len) return -1;
    return 0;
}

// 从 buffer 里按 SSH string 读
static int read_string(const unsigned char *p, size_t len, size_t *pos,
                       const unsigned char **out, size_t *out_len) {
    if (*pos + 4 > len) return -1;
    unsigned n = ((unsigned) p[*pos] << 24) | ((unsigned) p[*pos + 1] << 16)
               | ((unsigned) p[*pos + 2] << 8) | p[*pos + 3];
    *pos += 4;
    if (*pos + n > len) return -1;
    *out = p + *pos;
    *out_len = n;
    *pos += n;
    return 0;
}

// ---------------------------------------------------------------- 拉起 app 签名

static void logf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/**
 * 让 app 对 data 签名。返回 malloc 的签名 blob（SSH 格式），失败返回 NULL。
 * key_b64  公钥 blob 的 base64（app 用它找密钥）
 * data     待签数据
 */
static unsigned char *ask_app_sign(const char *key_b64, const unsigned char *data,
                                   size_t data_len, const char *peer_ip,
                                   const unsigned char *hostkey, size_t hostkey_len,
                                   const unsigned char *session_id, size_t session_id_len,
                                   const unsigned char *bind_sig, size_t bind_sig_len,
                                   const char *target, size_t *sig_out_len) {
    char *data_b64 = b64_encode(data, data_len);
    char *hostkey_b64 = (hostkey && hostkey_len > 0) ? b64_encode(hostkey, hostkey_len) : NULL;
    char *sid_b64 = (session_id && session_id_len > 0) ? b64_encode(session_id, session_id_len) : NULL;
    char *sig_b64 = (bind_sig && bind_sig_len > 0) ? b64_encode(bind_sig, bind_sig_len) : NULL;
    if (!data_b64) { free(hostkey_b64); free(sid_b64); free(sig_b64); return NULL; }

    // 临时本地 socket，app 签完写结果
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { free(data_b64); return NULL; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(lfd, (struct sockaddr *) &sa, sizeof sa) < 0 || listen(lfd, 1) < 0) {
        close(lfd);
        free(data_b64);
        return NULL;
    }
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *) &sa, &sl);
    char port_str[16];
    snprintf(port_str, sizeof port_str, "%u", ntohs(sa.sin_port));

    char *argv[] = {
            "am", "start", "-n", SIGN_COMPONENT,
            "--es", "key", (char *) key_b64,
            "--es", "data", data_b64,
            "--es", "host", "127.0.0.1",
            "--ei", "port", port_str,
            "--es", "peer", (char *) (peer_ip ? peer_ip : ""),
            "--es", "hostkey", hostkey_b64 ? hostkey_b64 : "",
            "--es", "session_id", sid_b64 ? sid_b64 : "",
            "--es", "bind_sig", sig_b64 ? sig_b64 : "",
            "--es", "server", (char *) (target ? target : ""),
            NULL
    };
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }
        execv(AM_PATH, argv);
        _exit(127);
    }
    if (pid > 0) waitpid(pid, NULL, 0);
    free(data_b64);
    free(hostkey_b64);
    free(sid_b64);
    free(sig_b64);

    // 等 app 回传
    struct pollfd pfd = {.fd = lfd, .events = POLLIN};
    int pr = poll(&pfd, 1, SIGN_TIMEOUT_MS);
    if (pr <= 0) {
        logf("签名超时/无回应（app 没拉起或指纹未通过）");
        close(lfd);
        return NULL;
    }
    int cfd = accept(lfd, NULL, NULL);
    close(lfd);
    if (cfd < 0) return NULL;

    char line[8192];
    ssize_t n = read(cfd, line, sizeof line - 1);
    close(cfd);
    if (n <= 0) return NULL;
    line[n] = 0;
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;

    if (strncmp(line, "OK ", 3) != 0) {
        logf("app 拒绝签名: %s", line);
        return NULL;
    }
    size_t raw_len = 0;
    unsigned char *raw = b64_decode(line + 3, &raw_len);
    if (!raw) return NULL;
    *sig_out_len = raw_len;
    return raw;
}

// ---------------------------------------------------------------- 连接处理

typedef struct {
    unsigned char *hostkey;     /* 服务器 host key blob（来自 session-bind） */
    size_t hostkey_len;
    unsigned char *session_id;  /* KEX exchange hash */
    size_t session_id_len;
    unsigned char *bind_sig;    /* 服务器对 session_id 的签名（app 端用 BC 验签） */
    size_t bind_sig_len;
} conn_ctx_t;

static void handle_conn(int fd, const char *peer_ip) {
    /* PC 侧包装脚本会把目标主机通过一行前缀送进来：KSV_TARGET <host>\n
     * 这是"服务器 IP 从哪来"的唯一来源（agent 协议本身不带目标地址）。 */
    char target[128];
    target[0] = 0;
    {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 500) > 0) {
            char peek[16];
            ssize_t pn = recv(fd, peek, sizeof peek, MSG_PEEK);
            if (pn >= 11 && memcmp(peek, "KSV_TARGET ", 11) == 0) {
                char line[160];
                ssize_t got = 0;
                while (got < (ssize_t) sizeof line - 1) {
                    char c;
                    if (read(fd, &c, 1) != 1) break;
                    if (c == '\n') break;
                    line[got++] = c;
                }
                line[got] = 0;
                if (got > 11) snprintf(target, sizeof target, "%s", line + 11);
            }
        }
    }
    if (target[0]) logf("target=%s (from %s)", target, peer_ip);
    conn_ctx_t ctx = {0};
    buf_t pkt;
    while (read_packet(fd, &pkt) == 0) {
        unsigned type = pkt.p[0];
        buf_t resp;
        buf_init(&resp);

        if (type == SSH_AGENTC_EXTENSION) {
            /* OpenSSH 扩展：query / session-bind@openssh.com
             * session-bind 里带着服务器 host key（含服务器对 session 的签名），
             * 这是 agent 能拿到的唯一可信服务器身份。 */
            size_t pos = 1;
            const unsigned char *name = NULL;
            size_t nlen = 0;
            if (read_string(pkt.p, pkt.len, &pos, &name, &nlen) != 0) {
                buf_put(&resp, (unsigned char[]) {SSH_AGENT_EXTENSION_FAILURE}, 1);
            } else if (nlen == 24 && memcmp(name, "session-bind@openssh.com", 24) == 0) {
                const unsigned char *hk = NULL, *sid = NULL, *sig = NULL;
                size_t hlen = 0, slen = 0, siglen2 = 0;
                if (read_string(pkt.p, pkt.len, &pos, &hk, &hlen) == 0 &&
                    read_string(pkt.p, pkt.len, &pos, &sid, &slen) == 0 &&
                    read_string(pkt.p, pkt.len, &pos, &sig, &siglen2) == 0 &&
                    hlen > 0 && hlen < 65536 && slen > 0 && slen < 4096 &&
                    siglen2 > 0 && siglen2 < 65536) {
                    /* 先全部申请成功再替换，避免半新半旧的状态 */
                    unsigned char *nhk = malloc(hlen);
                    unsigned char *nsid = malloc(slen);
                    unsigned char *nsig = malloc(siglen2);
                    if (nhk && nsid && nsig) {
                        memcpy(nhk, hk, hlen);
                        memcpy(nsid, sid, slen);
                        memcpy(nsig, sig, siglen2);
                        free(ctx.hostkey); free(ctx.session_id); free(ctx.bind_sig);
                        ctx.hostkey = nhk;
                        ctx.hostkey_len = hlen;
                        ctx.session_id = nsid;
                        ctx.session_id_len = slen;
                        ctx.bind_sig = nsig;
                        ctx.bind_sig_len = siglen2;
                        logf("session-bind: hostkey %zuB sid %zuB sig %zuB (from %s)",
                             hlen, slen, siglen2, peer_ip);
                        buf_put(&resp, (unsigned char[]) {SSH_AGENT_SUCCESS}, 1);
                    } else {
                        free(nhk); free(nsid); free(nsig);
                        buf_put(&resp, (unsigned char[]) {SSH_AGENT_EXTENSION_FAILURE}, 1);
                    }
                } else {
                    buf_put(&resp, (unsigned char[]) {SSH_AGENT_EXTENSION_FAILURE}, 1);
                }
            } else if (nlen == 5 && memcmp(name, "query", 5) == 0) {
                static const char kExt[] = "session-bind@openssh.com";
                buf_put(&resp, (unsigned char[]) {SSH_AGENT_EXTENSION_RESPONSE}, 1);
                buf_string(&resp, "query", 5);
                buf_string(&resp, kExt, sizeof kExt - 1);
            } else {
                logf("unsupported extension %.*s", (int) nlen, name);
                buf_put(&resp, (unsigned char[]) {SSH_AGENT_EXTENSION_FAILURE}, 1);
            }

        } else if (type == SSH2_AGENTC_REQUEST_IDENTITIES) {
            ksv_key_t *keys = NULL;
            int n = load_pubkeys(&keys);

            // 先收集能解析的条目，再一次性写答案（避免计数和内容对不上）
            buf_t list;
            buf_init(&list);
            unsigned count = 0;
            for (int i = 0; i < n; i++) {
                size_t blen = 0;
                unsigned char *blob = b64_decode(keys[i].pub, &blen);
                if (blob) {
                    buf_string(&list, blob, blen);
                    buf_string(&list, keys[i].comment, strlen(keys[i].comment));
                    count++;
                    free(blob);
                }
                free(keys[i].pub);
                free(keys[i].comment);
            }
            free(keys);

            buf_put(&resp, (unsigned char[]) {SSH2_AGENT_IDENTITIES_ANSWER}, 1);
            buf_u32(&resp, count);
            if (list.len) buf_put(&resp, list.p, list.len);
            free(list.p);
            logf("identities -> %u key(s)", count);

        } else if (type == SSH2_AGENTC_SIGN_REQUEST) {
            size_t pos = 1;
            const unsigned char *keyblob = NULL, *data = NULL;
            size_t keylen = 0, datalen = 0;
            int ok = read_string(pkt.p, pkt.len, &pos, &keyblob, &keylen) == 0
                  && read_string(pkt.p, pkt.len, &pos, &data, &datalen) == 0;
            if (!ok) {
                buf_put(&resp, (unsigned char[]) {SSH_AGENT_FAILURE}, 1);
            } else {
                /* 打印 key blob 类型：hostbound 请求的类型名是 publickey-hostbound-v00@openssh.com */
                {
                    size_t p2 = 0;
                    const unsigned char *kt = NULL;
                    size_t ktl = 0;
                    if (read_string(keyblob, keylen, &p2, &kt, &ktl) == 0)
                        logf("sign req keytype=%.*s blob_len=%zu", (int) ktl, kt, keylen);
                }
                char *key_b64 = b64_encode(keyblob, keylen);
                size_t siglen = 0;
                unsigned char *sig = key_b64
                        ? ask_app_sign(key_b64, data, datalen, peer_ip,
                                   ctx.hostkey, ctx.hostkey_len,
                                   ctx.session_id, ctx.session_id_len,
                                   ctx.bind_sig, ctx.bind_sig_len,
                                   target, &siglen) : NULL;
                free(key_b64);
                if (sig) {
                    buf_put(&resp, (unsigned char[]) {SSH2_AGENT_SIGN_RESPONSE}, 1);
                    buf_string(&resp, sig, siglen);
                    free(sig);
                    logf("signed %zu bytes", datalen);
                } else {
                    buf_put(&resp, (unsigned char[]) {SSH_AGENT_FAILURE}, 1);
                }
            }

        } else {
            buf_put(&resp, (unsigned char[]) {SSH_AGENT_FAILURE}, 1);
            logf("unsupported msg %u", type);
        }

        if (write_packet(fd, &resp) < 0) {
            free(resp.p);
            break;
        }
        free(resp.p);
        free(pkt.p);
    }
    free(pkt.p);
    free(ctx.hostkey);
    free(ctx.session_id);
    free(ctx.bind_sig);
}

// ---------------------------------------------------------------- 模块存活监视

// 本进程若位于 Magisk/KSU 模块目录（/data/adb/modules/<id>/...），返回一个
// inotify fd 监听"模块目录被删除"；否则返回 -1（手动 /data/local/tmp 运行时不监视）。
// out_id 带回模块 id。
static int watch_module_dir(char *out_dir, size_t dlen, char *out_id, size_t idlen) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0) return -1;
    exe[n] = '\0';

    static const char base[] = "/data/adb/modules";
    if (strncmp(exe, base, sizeof base - 1) != 0) return -1;

    char *p = exe + sizeof base - 1;
    if (strncmp(p, "_update", 7) == 0) p += 7;   // 装完还没重启时在 modules_update
    if (*p != '/') return -1;

    char *id = p + 1;
    char *slash = strchr(id, '/');
    if (!slash) return -1;              // 直接躺在 modules/ 下，不是模块
    *slash = '\0';                      // exe 截断成模块目录
    if (strlen(id) >= idlen) return -1;
    snprintf(out_id, idlen, "%s", id);

    if (strlen(exe) >= dlen) return -1;
    snprintf(out_dir, dlen, "%s", exe);

    char parent[PATH_MAX];
    snprintf(parent, sizeof parent, "%s", exe);
    char *ps = strrchr(parent, '/');
    if (!ps) return -1;
    *ps = '\0';

    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return -1;

    // 目录自身被删除 / 被移走
    if (inotify_add_watch(fd, exe, IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR) < 0) {
        close(fd);
        return -1;
    }
    // 父目录里 <id> 被删除（rm -rf 时先收到这一条）
    if (inotify_add_watch(fd, parent, IN_DELETE) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// 读空 inotify 队列；返回 1 表示模块目录已消失
static int module_dir_gone(int fd, const char *id) {
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) return 0;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *) p;
            if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) return 1;
            if ((ev->mask & IN_DELETE) && ev->len > 0 && strcmp(ev->name, id) == 0) return 1;
            p += sizeof(struct inotify_event) + ev->len;
        }
    }
}

// ---------------------------------------------------------------- UDP 发现

// 局域网内 PC 发 KSV_DISCOVER 到 7023，这里回一个 JSON 告诉它端口和机型
static int setup_discovery(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(DISCOVERY_PORT);
    if (bind(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void answer_discovery(int fd) {
    char req[64];
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    ssize_t n = recvfrom(fd, req, sizeof req - 1, 0, (struct sockaddr *) &from, &flen);
    if (n <= 0) return;
    req[n] = '\0';
    if (strcmp(req, DISCOVER_PROBE) != 0) return;

    char model[PROP_VALUE_MAX] = "";
    __system_property_get("ro.product.model", model);
    char resp[256];
    snprintf(resp, sizeof resp, "{\"tcp\":%d,\"name\":\"%s\"}", LISTEN_PORT,
             model[0] ? model : "android");
    sendto(fd, resp, strlen(resp), 0, (struct sockaddr *) &from, flen);
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(LISTEN_PORT);
    if (bind(lfd, (struct sockaddr *) &sa, sizeof sa) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 16) < 0) { perror("listen"); return 1; }

    logf("ksv-agent listening on 0.0.0.0:%d", LISTEN_PORT);

    char mod_id[64] = "";
    char mod_dir[PATH_MAX] = "";
    int ifd = watch_module_dir(mod_dir, sizeof mod_dir, mod_id, sizeof mod_id);
    if (ifd >= 0) logf("监视模块目录 %s（被删除时退出）", mod_dir);

    int dfd = setup_discovery();
    if (dfd >= 0) logf("UDP 发现在 %d 上待命", DISCOVERY_PORT);

    for (;;) {
        struct pollfd pfd[3];
        int nfds = 0;
        int i_lfd = nfds++;
        pfd[i_lfd].fd = lfd;
        pfd[i_lfd].events = POLLIN;
        pfd[i_lfd].revents = 0;
        int i_ifd = -1, i_dfd = -1;
        if (ifd >= 0) {
            i_ifd = nfds++;
            pfd[i_ifd].fd = ifd;
            pfd[i_ifd].events = POLLIN;
            pfd[i_ifd].revents = 0;
        }
        if (dfd >= 0) {
            i_dfd = nfds++;
            pfd[i_dfd].fd = dfd;
            pfd[i_dfd].events = POLLIN;
            pfd[i_dfd].revents = 0;
        }

        int pr = poll(pfd, nfds, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (i_dfd >= 0 && (pfd[i_dfd].revents & POLLIN)) answer_discovery(dfd);
        if (i_ifd >= 0 && (pfd[i_ifd].revents & POLLIN) && module_dir_gone(ifd, mod_id)) {
            logf("模块 %s 已被移除，退出", mod_id);
            break;
        }
        if (!(pfd[i_lfd].revents & POLLIN)) continue;

        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int c = accept(lfd, (struct sockaddr *) &peer, &plen);
        if (c < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char peer_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof peer_ip) == NULL) {
            strcpy(peer_ip, "?");
        }
        if (fork() == 0) {
            close(lfd);
            if (ifd >= 0) close(ifd);
            if (dfd >= 0) close(dfd);
            handle_conn(c, peer_ip);
            close(c);
            _exit(0);
        }
        close(c);
    }
    if (ifd >= 0) close(ifd);
    if (dfd >= 0) close(dfd);
    close(lfd);
    return 0;
}
