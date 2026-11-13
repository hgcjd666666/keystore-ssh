#!/usr/bin/env python3
"""
phone-agent —— PC 侧守护程序，把手机上的 SSH agent 变成本地可用的 SSH_AUTH_SOCK。

手机端（KeystoreSSH 的 AgentService）提供两个入口：
  · 抽象 socket @ksu_ssh_agent（手机上本机用）
  · TCP <lan-ip>:7022（局域网用，每次签名要指纹）

本程序在电脑上：
  serve   常驻监听 unix socket，把每个连接透明转发到手机 TCP。
          断线自动关闭该连接，下一次连接会重新拨号，不需要重启守护程序。
  list    连手机发 REQUEST_IDENTITIES，列出所有公钥（comment + 指纹 + 公钥行）
  export  导出某把钥匙的公钥行，可直接 >> ~/.ssh/authorized_keys
  check   测一下手机 agent 是否在线

用法：
  phone-agent serve  --host 192.168.2.5 --port 7022
  phone-agent list   --host 192.168.2.5
  phone-agent export dsh --host 192.168.2.5
  phone-agent check  --host 192.168.2.5

环境变量 PHONE_AGENT_HOST / PHONE_AGENT_PORT / PHONE_AGENT_SOCK 可代替参数。
"""
import argparse
import atexit
import base64
import hashlib
import json
import os
import socket
import signal
import struct
import sys
import threading
import time

SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_SIGN_RESPONSE = 14

DEFAULT_PORT = 7022
DISCOVERY_PORT = 7023
DISCOVER_PROBE = b"KSV_DISCOVER"


# ---------------------------------------------------------------- 协议工具

def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def s(b: bytes) -> bytes:
    return u32(len(b)) + b


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def u32(self) -> int:
        v = struct.unpack(">I", self.data[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def string(self) -> bytes:
        n = self.u32()
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def recv_packet(sock: socket.socket) -> bytes:
    length = struct.unpack(">I", read_exact(sock, 4))[0]
    if length == 0 or length > (1 << 20):
        raise IOError(f"bad packet length {length}")
    return read_exact(sock, length)


def send_packet(sock: socket.socket, payload: bytes):
    sock.sendall(u32(len(payload)) + payload)


def fingerprint(pub_blob: bytes) -> str:
    d = hashlib.sha256(pub_blob).digest()
    return "SHA256:" + base64.b64encode(d).decode().rstrip("=")


def key_type(pub_blob: bytes) -> str:
    try:
        return Reader(pub_blob).string().decode()
    except Exception:
        return "?"


def public_line(pub_blob: bytes, comment: str) -> str:
    """还原成 authorized_keys 里那一行"""
    line = f"{key_type(pub_blob)} {base64.b64encode(pub_blob).decode()}"
    return f"{line} {comment}" if comment else line


# ---------------------------------------------------------------- 与手机通信

def connect_phone(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def fetch_identities(host: str, port: int):
    """返回 [(stdout_line, pub_blob, comment), ...]"""
    sock = connect_phone(host, port)
    try:
        send_packet(sock, bytes([SSH2_AGENTC_REQUEST_IDENTITIES]))
        packet = recv_packet(sock)
    finally:
        sock.close()
    if packet[0] != SSH2_AGENT_IDENTITIES_ANSWER:
        raise IOError(f"unexpected answer type {packet[0]}")
    r = Reader(packet, 1)
    n = r.u32()
    out = []
    for _ in range(n):
        blob = r.string()
        comment = r.string().decode(errors="replace")
        out.append((public_line(blob, comment), blob, comment))
    return out


def sign_data(host: str, port: int, pub_blob: bytes, data: bytes) -> bytes:
    """让手机对 data 签名，返回签名 blob（手机端会弹指纹，所以超时给足）"""
    sock = connect_phone(host, port, timeout=120.0)
    try:
        payload = bytes([SSH2_AGENTC_SIGN_REQUEST]) + s(pub_blob) + s(data) + u32(0)
        send_packet(sock, payload)
        packet = recv_packet(sock)
    finally:
        sock.close()
    if packet[0] != SSH2_AGENT_SIGN_RESPONSE:
        raise IOError(f"agent 拒绝了签名请求（type={packet[0]}），可能是手机侧没指纹通过")
    return Reader(packet, 1).string()


# ---------------------------------------------------------------- 子命令

def cmd_serve(args):
    host, port, sock_path = args.host, args.port, args.sock
    auto = host in ("", "auto")
    phone = {"ip": None if auto else host, "port": port}
    lock = threading.Lock()

    def resolve(reprobe: bool = False):
        """返回 (ip, port)。auto 模式下连不上就重新在局域网里找"""
        if not auto:
            return phone["ip"], phone["port"]
        with lock:
            if reprobe or not phone["ip"]:
                found = probe(wait=max(1.0, args.wait), quiet=True)
                if found:
                    ip = sorted(found)[0]
                    phone["ip"] = ip
                    phone["port"] = int(found[ip].get("tcp") or port)
                    print(f"[phone-agent] 发现手机 {ip}:{phone['port']} "
                          f"{found[ip].get('name', '')}", flush=True)
                elif reprobe:
                    print("[phone-agent] 局域网里没找到手机", flush=True)
            return phone["ip"], phone["port"]

    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(16)

    def cleanup():
        try:
            os.unlink(sock_path)
        except OSError:
            pass

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    print(f"[phone-agent] unix {sock_path} -> "
          f"{'auto（局域网发现）' if auto else f'tcp {host}:{port}'}", flush=True)
    if auto:
        resolve()

    def pump(src: socket.socket, dst: socket.socket):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def handle(client: socket.socket):
        upstream = None
        try:
            for attempt in (0, 1):
                ip, pt = resolve(reprobe=attempt > 0)
                if not ip:
                    continue
                try:
                    upstream = connect_phone(ip, pt, timeout=10.0)
                    break
                except OSError as e:
                    print(f"[phone-agent] 连 {ip}:{pt} 失败: {e}", flush=True)
                    phone["ip"] = None if auto else phone["ip"]
            if upstream is None:
                return
            upstream.settimeout(None)
            client.settimeout(None)
            t = threading.Thread(target=pump, args=(client, upstream), daemon=True)
            t.start()
            pump(upstream, client)
            t.join(timeout=1)
        except Exception as e:
            print(f"[phone-agent] conn error: {e}", flush=True)
        finally:
            for x in (client, upstream):
                if x is not None:
                    try:
                        x.close()
                    except OSError:
                        pass

    while True:
        try:
            conn, _ = srv.accept()
        except KeyboardInterrupt:
            break
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def cmd_list(args):
    keys = fetch_identities(args.host, args.port)
    if not keys:
        print("手机上一把钥匙都没有（先在 App 里生成）")
        return
    for line, blob, comment in keys:
        print(f"{comment or '(无 comment)'}")
        print(f"  指纹: {fingerprint(blob)}")
        print(f"  公钥: {line}")
        print()


def cmd_export(args):
    keys = fetch_identities(args.host, args.port)
    want = args.comment
    picked = [k for k in keys if k[2] == want]
    if not picked and want in ("", None) and len(keys) == 1:
        picked = keys
    if not picked:
        names = ", ".join(k[2] or "(空)" for k in keys) or "(无)"
        print(f"找不到 comment='{want}' 的公钥。手机上有: {names}", file=sys.stderr)
        return 1
    for line, _, _ in picked:
        print(line)
    return 0


def cmd_sign(args):
    keys = fetch_identities(args.host, args.port)
    picked = [k for k in keys if k[2] == args.comment]
    if not picked:
        print(f"找不到 comment='{args.comment}' 的密钥", file=sys.stderr)
        return 1
    data = sys.stdin.buffer.read() if args.data == "-" else open(args.data, "rb").read()
    sig = sign_data(args.host, args.port, picked[0][1], data)
    print(base64.b64encode(sig).decode())
    return 0


def cmd_check(args):
    t0 = time.time()
    try:
        keys = fetch_identities(args.host, args.port)
    except Exception as e:
        print(f"✗ 连不上手机 agent {args.host}:{args.port} —— {e}")
        return 1
    ms = int((time.time() - t0) * 1000)
    print(f"✓ 手机 agent 在线，{len(keys)} 把钥匙，往返 {ms}ms")
    for _, _, comment in keys:
        print(f"  - {comment or '(无 comment)'}")
    return 0


def local_hosts():
    """枚举本机各物理网卡所在子网里的其他主机 IP（跳过虚拟网卡）"""
    import fcntl
    hosts = []
    try:
        ifaces = os.listdir("/sys/class/net")
    except OSError:
        return hosts
    skip = ("lo", "vir", "docker", "br-", "veth", "tun", "tap", "wg", "zt", "vnet")
    for ifname in ifaces:
        if ifname.startswith(skip):
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            addr = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(), 0x8915, struct.pack("256s", ifname.encode()[:15]))[20:24])
            mask = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(), 0x891b, struct.pack("256s", ifname.encode()[:15]))[20:24])
            s.close()
        except OSError:
            continue
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(addr))[0]
            mask_int = struct.unpack("!I", socket.inet_aton(mask))[0]
            net = ip_int & mask_int
            host_bits = 32 - bin(mask_int).count("1")
            if host_bits < 8 or host_bits > 16:
                continue  # 只扫 /24 到 /16 之间的常见内网
            count = (1 << host_bits) - 1
            for i in range(1, count):
                candidate = socket.inet_ntoa(struct.pack("!I", net + i))
                if candidate != addr:
                    hosts.append(candidate)
        except Exception:
            continue
    return hosts


def probe(wait: float = 2.0, quiet: bool = False) -> dict:
    """在局域网里找手机 agent：广播 + 子网单播扫描双管齐下。返回 {ip: info}"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)

    sent = 0
    # 1) 广播（不少 WiFi 会过滤，聊胜于无）
    for tgt in {("255.255.255.255", DISCOVERY_PORT)}:
        try:
            sock.sendto(DISCOVER_PROBE, tgt)
            sent += 1
        except OSError:
            pass
    # 2) 子网单播扫描（可靠路径）；非阻塞发送，不会被 ARP 拖住
    hosts = local_hosts()
    for ip in hosts:
        try:
            sock.sendto(DISCOVER_PROBE, (ip, DISCOVERY_PORT))
            sent += 1
        except OSError:
            continue

    sock.setblocking(True)
    sock.settimeout(0.2)

    if not quiet:
        print(f"已探测 {sent} 个地址（广播 + {len(hosts)} 个单播），等待 {wait:.1f}s…", file=sys.stderr)

    found = {}
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            info = json.loads(data.decode())
        except Exception:
            continue
        found[addr[0]] = info
    sock.close()
    return found


def cmd_discover(args):
    found = probe(wait=args.wait)
    if not found:
        print("没有发现手机 agent。(检查: 手机和电脑同一局域网 / App 里开了「局域网」/ 服务在跑)")
        return 1
    for ip in sorted(found):
        i = found[ip]
        print(f"✓ {ip}:{i.get('tcp', '?')}  {i.get('name', '?')}  keys={i.get('keys', '?')}")
    return 0


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(description="PC 侧 SSH agent 转发/管理工具")
    ap.add_argument("cmd", choices=["serve", "list", "export", "sign", "check", "discover"],
                    help="serve 常驻转发 / list 列公钥 / export 导出 / sign 签名 / check 探活 / discover 内网发现")
    ap.add_argument("arg1", nargs="?", default="",
                    help="export: comment；sign: comment")
    ap.add_argument("arg2", nargs="?", default="",
                    help="sign: 数据文件路径或 -")
    ap.add_argument("--host", default=os.environ.get("PHONE_AGENT_HOST", ""),
                    help="手机 IP（或设 PHONE_AGENT_HOST）")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("PHONE_AGENT_PORT", DEFAULT_PORT)),
                    help=f"手机 agent 端口，默认 {DEFAULT_PORT}")
    ap.add_argument("--sock", default=os.environ.get(
                        "PHONE_AGENT_SOCK",
                        os.path.expanduser("~/.ssh/phone-agent.sock")),
                    help="本地 unix socket 路径（serve 用）")
    ap.add_argument("--wait", type=float, default=2.0,
                    help="discover 等待应答的秒数，默认 2")
    args = ap.parse_args()

    if args.cmd in ("serve", "list", "export", "sign", "check") and not args.host \
            and args.cmd != "serve":
        print("需要 --host（或 PHONE_AGENT_HOST 环境变量）", file=sys.stderr)
        return 2

    # 非 serve 的单次命令：--host auto 就地探测一次
    if args.host == "auto" and args.cmd != "serve":
        found = probe(wait=args.wait, quiet=True)
        if not found:
            print("局域网里没找到手机 agent", file=sys.stderr)
            return 1
        ip = sorted(found)[0]
        args.port = int(found[ip].get("tcp") or args.port)
        args.host = ip

    if args.cmd == "export":
        args.comment = args.arg1
    elif args.cmd == "sign":
        args.comment = args.arg1
        args.data = args.arg2
        if not args.data:
            print("sign 需要 comment 和数据文件（或 -）", file=sys.stderr)
            return 2

    handlers = {
        "serve": cmd_serve, "list": cmd_list, "export": cmd_export,
        "sign": cmd_sign, "check": cmd_check, "discover": cmd_discover,
    }
    return handlers[args.cmd](args) or 0


if __name__ == "__main__":
    sys.exit(main())
