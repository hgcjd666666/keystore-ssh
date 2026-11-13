# 只用 BC 的 Ed25519 实现，其余交给 R8 静态裁剪
-keep class org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters { *; }
-keep class org.bouncycastle.crypto.params.Ed25519PublicKeyParameters { *; }
-keep class org.bouncycastle.crypto.signers.Ed25519Signer { *; }
-dontwarn org.bouncycastle.**

# Activity 入口（manifest 已引用，R8 会保留，这里显式声明更稳）
-keep class com.dsh.keystore.MainActivity { *; }
-keep class com.dsh.keystore.SignActivity { *; }
