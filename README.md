# KeystoreSSH

私钥保存在手机的 Android Keystore 里（需要有效的 TEE），电脑需要连接服务器的时候，向手机请求签名

## 结构

```
电脑                                    手机
────                                    ────
ssh ──> ~/.ssh/phone-agent.sock         KeystoreSSH app（Keystore + 指纹）
              │                                ▲
        phone-agent.py（PC 侧桥接）             │ 一次性回传 socket
              │ TCP 7022                      │
              └──────────> ksv-agent ─────────┘
                           （root，模块开机自启）
```

- `ksv-agent` 只跑 ssh-agent 协议，私钥碰不到，它负责在需要签名时把 app 拉起来
- app 用 `BiometricPrompt` 进行生物识别，授权后去用私钥签名
- 签名前会用 hostbound 里的 hostkey 校验服务器身份，对不上就拒绝，防止中间人攻击

## 安装

### 1. 手机装 app

`keystore-ssh-v0.2.apk`，打开后生成一把密钥，或者粘贴已有的 OpenSSH Ed25519 私钥导入

### 2. 手机装模块（需要 root）

`keystore-ssh-v0.2.zip`，在 Magisk / KernelSU 里安装，重启

模块里只有一个 `ksv-agent`，重启后会在 late_start service 阶段自己起来监听 7022
或者你也可以让ai魔改一个shell权限的守护进程（类似shizuku那种）

### 3. 电脑装桥接

```bash
git clone https://github.com/hgcjd666666/keystore-ssh
cd keystore-ssh/pc
./install.sh
```

## 使用

```bash
export SSH_AUTH_SOCK=$HOME/.ssh/phone-agent.sock
ssh root@你的服务器
```

手机弹指纹，按了就进去。

常驻的话写进 `~/.ssh/config`：

```
Host *
    IdentityAgent ~/.ssh/phone-agent.sock
```

## 多把密钥

agent 里可以放多把。ssh 先从手机拿到公钥列表，再逐把向服务器探测，服务器认可哪把就用哪把签名（这个机制真好用）

`phone-agent.py` 还有几个不依赖 `SSH_AUTH_SOCK` 的小命令：

```bash
python3 pc/phone-agent.py list      --host auto    # 列手机上的公钥
python3 pc/phone-agent.py export    dsh --host auto # 导出某把公钥
python3 pc/phone-agent.py check     --host auto    # 测试连接
python3 pc/phone-agent.py discover                  # 找局域网里的手机
```

## 构建

```bash
./build.sh debug     # 调试包
./build.sh release   # 正式包（R8）
./build.sh agent     # 只编 C agent（aarch64）
./build.sh module    # 打 Magisk/KernelSU 模块 zip
```

需要 `JAVA_HOME`、`ANDROID_HOME`、`GRADLE`；编 agent 还要 NDK。

## 安全边界

- 私钥由 TEE 里的 KEK 加密，`setUserAuthenticationRequired`，每次使用都要指纹，没有设计导出功能
- agent 只转发协议，被攻破也拿不到私钥，密钥在 TEE 里（你要 root 装模块当我没说，但 teesimulator 在我手机上不会影响 TEE，还能正常使用 TEE）
- 就算有arp欺骗也会让你签名（你连没连ssh你不知道？！）
- 公钥会在探测阶段发给服务器看，这是openssh本身的机制

## 目录

```
app/        Android app（Compose UI、Keystore 密钥库、签名 Activity）
agent/      ksv-agent.c，root 侧 ssh-agent 网关（纯 C）
pc/         phone-agent.py + install.sh，PC 侧桥接
magisk/     Magisk / KernelSU 模块骨架
```
