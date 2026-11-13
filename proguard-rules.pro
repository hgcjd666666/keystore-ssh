# BouncyCastle：大量反射/服务发现，整体保留
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# org.json 结构反射
-keep class org.json.** { *; }

# Compose 运行时由自带规则处理；这里只需保住 Activity/Service 入口
-keep class com.dsh.keystore.MainActivity { *; }
-keep class com.dsh.keystore.SignActivity { *; }
