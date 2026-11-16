// ksv-agent: root 侧 ssh-agent 网关（纯 C，不碰私钥）
//
// 职责：
//   · 监听 TCP 7022，跑 ssh-agent 协议
//   · 可选：额外监听一个 unix socket，路径由启动参数传入，给本机 openssh 直接当
//     SSH_AUTH_SOCK 用（export SSH_AUTH_SOCK=/data/local/tmp/ksv-agent.sock）
//   · REQUEST_IDENTITIES -> 读 app 的 shared_prefs（只有公钥）
//   · SIGN_REQUEST       -> am start 拉起 app 的 SignActivity，把待签数据放 Intent extras，
//                           签名结果由 app 通过本进程开的临时 socket 回传
//
// 私钥始终在 app 的 Keystore 里，本进程只转发协议。
//
// 守护化（等 boot_completed、日志文件、单实例检查）都在本程序里，
// 路径由启动参数给出；单实例直接看 unix socket 在不在、连不连得上，
// 不需要额外的锁文件。
//
// 编译：NDK clang -O2 -o ksv-agent ksv-agent.c
// 运行：
//   su -c '/data/local/tmp/ksv-agent -s /data/local/tmp/ksv-agent.sock \
//          -l /data/local/tmp/ksv-agent.log'
//
// 模块卸载后本来就得重启，所以不需要 uninstall.sh，也不做存活监视。

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
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif
#include <limits.h>
#include <unistd.h>

#define LISTEN_PORT      7022
#define DISCOVERY_PORT   7023
#define DISCOVER_PROBE   "KSV_DISCOVER"
#define PREFS_PATH       "/data/data/com.dsh.keystore/shared_prefs/ssh_vault.xml"
#define AM_PATH          "/system/bin/am"
#define SIGN_COMPONENT   "com.dsh.keystore/.SignActivity"
#define SIGN_TIMEOUT_MS  120000

// 实际监听的 TCP 端口：7022 被占用时退避到内核分配的随机端口，
// UDP 发现会把这个值回报给 PC，所以端口变了也不影响连接。
static int g_listen_port = LISTEN_PORT;

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
// app 的 shared_prefs（key_entries 里 pubBlob/comment 是明文 JSON）
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
    *out = NULL;
    return 0;
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

// ---------------------------------------------------------------- UDP 发现

// 局域网内 PC 发 KSV_DISCOVER 到 7023，这里回个端口号
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

    char resp[16];
    int n2 = snprintf(resp, sizeof resp, "%d", g_listen_port);
    sendto(fd, resp, (size_t) n2, 0, (struct sockaddr *) &from, flen);
}

// ---------------------------------------------------------------- unix socket

/**
 * 监听一个 unix 域 socket，供本机进程（openssh）直接使用。
 *
 * 路径由启动参数给出，本程序不猜默认值。绑定前会清掉上次运行残留的
 * socket 文件；路径上如果是普通文件/目录就拒绝，避免误删。
 * 权限交给调用方（server.sh 按需 chmod），这里只保证 bind+listen。
 */
static int setup_unix_listener(const char *path) {
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(sa.sun_path, path);

    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            errno = EEXIST;     // 路径已被别的文件占了，不能动
            return -1;
        }
        unlink(path);           // 上次的残留 socket 文件
    } else if (errno != ENOENT) {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    if (listen(fd, 16) < 0) {
        int e = errno;
        close(fd);
        unlink(path);
        errno = e;
        return -1;
    }
    return fd;
}

/**
 * 探测 unix socket 是否还有活着的监听者：connect 成功就说明有人 listen，
 * 顺便用 SO_PEERCRED 拿到对端 pid。返回 1=活着，0=不存在或只是残留文件。
 */
static int socket_alive(const char *path, pid_t *out_pid) {
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa.sun_path) return 0;
    strcpy(sa.sun_path, path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    int alive = 0;
    if (connect(fd, (struct sockaddr *) &sa, sizeof sa) == 0) {
        alive = 1;
        if (out_pid) {
            struct ucred cr;
            socklen_t cl = sizeof cr;
            *out_pid = 0;
            if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) *out_pid = cr.pid;
        }
    }
    close(fd);
    return alive;
}

// ---------------------------------------------------------------- 守护化
// 这一节原来是 magisk/service.sh 里的 shell 逻辑：等 boot、日志文件、
// 单实例检查。现在全部搬进本程序（后台化交给启动脚本的 &）。
//
// 单实例不再用锁文件：unix socket 在、而且连得上，就说明另一个实例活着
// （还能从 SO_PEERCRED 拿到它的 pid）；连不上就是上次留下的死 socket，
// 直接清掉重绑。

/** 打开日志文件：存在就截断重写，不做轮转。 */
static int open_log(const char *path) {
    return open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
}

/** 把 stdout/stderr 接到日志文件。 */
static void redirect_log(int fd) {
    if (fd < 0) return;
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) close(fd);
}

/** sys.boot_completed 是否为 1（非 Android 构建下视为已完成）。 */
static int boot_completed(void) {
#ifdef __ANDROID__
    char v[PROP_VALUE_MAX];
    v[0] = 0;
    __system_property_get("sys.boot_completed", v);
    return v[0] == '1';
#else
    return 1;
#endif
}

// ---------------------------------------------------------------- 入口

static void usage(const char *argv0) {
    fprintf(stderr,
            "用法: %s [-s <unix socket>] [-p <tcp 端口>] [-l <日志>] "
            "[--no-wait-boot]\n"
            "  -s, --socket <路径>   unix socket 路径，给本机 openssh 当 SSH_AUTH_SOCK；\n"
            "                        这个 socket 还连得上就说明已有实例在跑，直接退出\n"
            "  -p, --port <端口>     TCP 端口（默认 %d；被占用时退避到随机端口）\n"
            "  -l, --log <文件>      日志文件：存在就截断重写，然后接管 stdout/stderr\n"
            "      --no-wait-boot    不等 sys.boot_completed\n"
            "  -h, --help            显示本帮助\n",
            argv0, LISTEN_PORT);
}

/** 绑定 TCP 监听；port=0 表示让内核分配随机端口。失败返回 -1。 */
static int make_tcp_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t) port);
    if (bind(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/** 子进程：关掉继承来的监听 fd，处理一条连接。 */
static void spawn_conn(int c, const char *peer, int lfd, int sfd, int dfd) {
    if (fork() == 0) {
        close(lfd);
        if (sfd >= 0) close(sfd);
        if (dfd >= 0) close(dfd);
        handle_conn(c, peer);
        close(c);
        _exit(0);
    }
    close(c);
}

int main(int argc, char **argv) {
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    const char *sock_path = NULL;
    const char *log_path = NULL;
    int want_port = LISTEN_PORT;
    int wait_boot = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--socket")) {
            if (++i >= argc) { usage(argv[0]); return 1; }
            sock_path = argv[i];
        } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (++i >= argc) { usage(argv[0]); return 1; }
            char *end = NULL;
            long v = strtol(argv[i], &end, 10);
            if (!end || *end || v <= 0 || v > 65535) {
                logf("端口无效: %s", argv[i]);
                return 1;
            }
            want_port = (int) v;
        } else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--log")) {
            if (++i >= argc) { usage(argv[0]); return 1; }
            log_path = argv[i];
        } else if (!strcmp(argv[i], "--no-wait-boot")) {
            wait_boot = 0;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-' && !sock_path) {
            sock_path = argv[i];        // 兼容 server.sh 直接传一个位置参数
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    // 日志：存在就截断重写，然后接管 stdout/stderr
    if (log_path) {
        int lf = open_log(log_path);
        if (lf < 0) {
            fprintf(stderr, "打开日志 %s 失败: %s\n", log_path, strerror(errno));
        } else {
            redirect_log(lf);
        }
    }

    // 单实例：socket 文件在而且连得上，说明另一个实例正活着
    if (sock_path) {
        pid_t owner = 0;
        if (socket_alive(sock_path, &owner)) {
            logf("已有实例在运行（%s，pid=%d），退出", sock_path, (int) owner);
            return 0;
        }
    }

    if (wait_boot) {
        int i;
        for (i = 0; i < 60 && !boot_completed(); i++) sleep(1);
        if (i >= 60) logf("等 sys.boot_completed 超时，照常启动");
    }

    int lfd = make_tcp_listener(want_port);
    if (lfd < 0) {
        // 端口被占就退避：让内核随机挑一个，UDP 发现会把真实端口报出去
        logf("TCP %d 绑定失败（%s），退避到随机端口", want_port, strerror(errno));
        lfd = make_tcp_listener(0);
        if (lfd < 0) { perror("bind"); return 1; }
    }
    {
        struct sockaddr_in got;
        socklen_t gl = sizeof got;
        if (getsockname(lfd, (struct sockaddr *) &got, &gl) == 0) {
            g_listen_port = ntohs(got.sin_port);
        }
    }
    logf("ksv-agent listening on 0.0.0.0:%d", g_listen_port);

    int sfd = -1;
    if (sock_path) {
        sfd = setup_unix_listener(sock_path);
        if (sfd < 0) {
            logf("unix socket %s 监听失败: %s", sock_path, strerror(errno));
            close(lfd);
            return 1;
        }
        logf("unix socket: %s（本机 openssh 可 export SSH_AUTH_SOCK=%s）", sock_path, sock_path);
    }

    int dfd = setup_discovery();
    if (dfd >= 0) logf("UDP 发现在 %d 上待命", DISCOVERY_PORT);

    for (;;) {
        struct pollfd pfd[4];
        int nfds = 0;
        int i_lfd = nfds++;
        pfd[i_lfd].fd = lfd;
        pfd[i_lfd].events = POLLIN;
        pfd[i_lfd].revents = 0;
        int i_dfd = -1, i_sfd = -1;
        if (dfd >= 0) {
            i_dfd = nfds++;
            pfd[i_dfd].fd = dfd;
            pfd[i_dfd].events = POLLIN;
            pfd[i_dfd].revents = 0;
        }
        if (sfd >= 0) {
            i_sfd = nfds++;
            pfd[i_sfd].fd = sfd;
            pfd[i_sfd].events = POLLIN;
            pfd[i_sfd].revents = 0;
        }

        int pr = poll(pfd, nfds, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (i_dfd >= 0 && (pfd[i_dfd].revents & POLLIN)) answer_discovery(dfd);
        // TCP 连接（PC 侧）
        if (pfd[i_lfd].revents & POLLIN) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof peer;
            int c = accept(lfd, (struct sockaddr *) &peer, &plen);
            if (c < 0) {
                if (errno == EINTR) continue;
                perror("accept");
                break;
            }
            char peer_ip[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof peer_ip) == NULL) {
                strcpy(peer_ip, "?");
            }
            spawn_conn(c, peer_ip, lfd, sfd, dfd);
        }

        // unix socket 连接（本机 openssh）
        if (i_sfd >= 0 && (pfd[i_sfd].revents & POLLIN)) {
            int c = accept(sfd, NULL, NULL);
            if (c < 0) {
                if (errno != EINTR) perror("accept(unix)");
                continue;
            }
            spawn_conn(c, "unix", lfd, sfd, dfd);
        }
    }
    if (sfd >= 0) {
        close(sfd);
        if (sock_path) unlink(sock_path);    // 退出时清掉 socket 文件
    }
    if (dfd >= 0) close(dfd);
    close(lfd);
    return 0;
}
