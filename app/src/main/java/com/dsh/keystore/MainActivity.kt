package com.dsh.keystore

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.security.SecureRandom
import javax.crypto.Cipher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * 主界面：Material 3 + Compose，跟 KernelSU 一样的卡片式布局。
 *
 *   密钥页：服务状态卡片 / 密钥卡片（comment + 指纹 + 操作）/ 生成·导入
 *   日志页：AgentLog 的实时环形日志
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            KeystoreSSHTheme {
                App(activity = this)
            }
        }
        try {
            AgentService.start(this)
        } catch (t: Throwable) {
            AgentLog.add("KeystoreSSH", "agent start failed: $t")
        }
    }
}

// ---------------------------------------------------------------- 视图模型

data class KeyVm(
    val id: String,
    val comment: String,
    val fingerprint: String,
    val pubLine: String,
)

data class SvcStatus(
    val running: Boolean,
    val tcpEnabled: Boolean,
    val port: Int,
    val keyCount: Int,
    val discoveryReady: Boolean = false,
    val startedAt: Long = 0L,
    val activeConns: Int = 0,
    val totalSigns: Int = 0,
    val lastSignAt: Long = 0L,
    val lastSignKey: String = "",
    val identitiesCalls: Int = 0,
)

// ---------------------------------------------------------------- 根界面

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(activity: Activity) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var tab by rememberSaveable { mutableIntStateOf(0) }
    var keys by remember { mutableStateOf<List<KeyVm>>(emptyList()) }
    var status by remember { mutableStateOf(SvcStatus(false, false, 0, 0)) }
    var logs by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }

    suspend fun refresh() {
        val app = ctx.applicationContext
        withContext(Dispatchers.IO) {
            keys = SshKeyVault.listEntries(app).map {
                KeyVm(it.id, it.comment, it.fingerprint(), it.pubLine)
            }
        }
        status = SvcStatus(
            running = AgentService.tcpReady,
            tcpEnabled = AgentService.tcpEnabled(app),
            port = if (AgentService.tcpPortBound > 0) AgentService.tcpPortBound
            else AgentService.tcpPort(app),
            keyCount = keys.size,
            discoveryReady = AgentService.discoveryReady,
            startedAt = AgentService.startedAt,
            activeConns = AgentService.activeConns,
            totalSigns = AgentService.totalSigns,
            lastSignAt = AgentService.lastSignAt,
            lastSignKey = AgentService.lastSignKey ?: "",
            identitiesCalls = AgentService.identitiesCalls,
        )
        logs = AgentLog.snapshot()
    }

    LaunchedEffect(Unit) {
        while (isActive) {
            try {
                refresh()
            } catch (t: Throwable) {
                AgentLog.add("UI", "refresh failed: $t")
            }
            delay(800)
        }
    }

    fun toast(s: String) {
        Toast.makeText(activity, s, Toast.LENGTH_SHORT).show()
    }

    fun copyPublic(key: KeyVm) {
        val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("ssh public key", key.pubLine))
        toast("公钥已复制")
        AgentLog.add("UI", "copied public key of ${key.comment.ifEmpty { key.id }}")
    }

    fun startAgent() {
        scope.launch {
            // 已经在跑就重启，让端口/配置变更立即生效
            if (AgentService.tcpReady) {
                activity.stopService(android.content.Intent(activity, AgentService::class.java))
                AgentLog.add("UI", "重启: 已请求停止旧实例")
                // 等旧实例真的释放端口，避免新实例 bind 撞车
                for (i in 0 until 12) {
                    delay(120)
                    if (!AgentService.tcpReady) break
                }
            }
            AgentService.start(activity)
            AgentLog.add("UI", "启动请求已发送，等待端口就绪…")

            // 最多等 3 秒，拿到真实结果再反馈，而不是只说"已请求"
            var result = "超时：3 秒内没等到 TCP 监听"
            val t0 = System.currentTimeMillis()
            for (i in 0 until 15) {
                delay(200)
                if (AgentService.tcpReady) {
                    val ms = System.currentTimeMillis() - t0
                    result = "已就绪 ${ms}ms: TCP " + AgentService.tcpPortBound
                    break
                }
            }
            AgentLog.add("UI", result)
            toast(result)
            refresh()
        }
    }

    fun generate(comment: String) {
        scope.launch {
            busy = true
            try {
                val res = withContext(Dispatchers.IO) {
                    SshKeyVault.ensureKek(true, true)
                    SshKeyGen.generate(comment, SecureRandom())
                }
                val pubBlob = SshKeyVault.unb64(res.publicLine.split(" ")[1])
                val ok = saveKey(activity, res.privatePem, res.publicLine, pubBlob, comment)
                AgentLog.add("UI", if (ok) "已生成并保存 $comment (${res.algo})" else "生成取消")
                if (ok) toast("已保存 $comment")
            } catch (t: Throwable) {
                AgentLog.add("UI", "generate failed: $t")
                toast("生成失败: ${t.message}")
            } finally {
                busy = false
            }
        }
    }

    fun import(pem: String) {
        scope.launch {
            busy = true
            try {
                val parsed = withContext(Dispatchers.IO) {
                    val seed = OpenSshKey.parseEd25519Seed(pem)
                    java.util.Arrays.fill(seed, 0)
                    val blob = OpenSshKey.parsePublicBlob(pem)
                    val c = OpenSshKey.parseComment(pem).ifEmpty { "imported" }
                    Triple(blob, c, "ssh-ed25519 ${SshKeyVault.b64(blob)} $c")
                }
                val (blob, comment, pubLine) = parsed
                val exists = withContext(Dispatchers.IO) { SshKeyVault.findByBlob(ctx, blob) != null }
                if (exists) {
                    AgentLog.add("UI", "导入跳过：这把公钥已存在")
                    toast("这把钥匙已经导入过了")
                    return@launch
                }
                val ok = saveKey(activity, pem, pubLine, blob, comment)
                AgentLog.add("UI", if (ok) "已导入 $comment" else "导入取消")
                if (ok) toast("已导入 $comment")
            } catch (t: Throwable) {
                AgentLog.add("UI", "import failed: $t")
                toast("导入失败: ${t.message}")
            } finally {
                busy = false
            }
        }
    }

    fun delete(key: KeyVm) {
        scope.launch {
            withContext(Dispatchers.IO) { SshKeyVault.removeEntry(ctx, key.id) }
            AgentLog.add("UI", "已删除 ${key.comment.ifEmpty { key.id }}")
            toast("已删除")
            refresh()
        }
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        "KeystoreSSH",
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0,
                    onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.Key, null) },
                    label = { Text("密钥") },
                )
                NavigationBarItem(
                    selected = tab == 1,
                    onClick = { tab = 1 },
                    icon = { Icon(Icons.Filled.Terminal, null) },
                    label = { Text("日志") },
                )
            }
        },
    ) { padding ->
        when (tab) {
            0 -> KeysScreen(
                modifier = Modifier.padding(padding),
                status = status,
                keys = keys,
                busy = busy,
                onStart = ::startAgent,
                onGenerate = ::generate,
                onImport = ::import,
                onCopy = ::copyPublic,
                onDelete = ::delete,
                onTcpSave = { enabled, port ->
                    activity.getSharedPreferences(AgentService.PREF, Context.MODE_PRIVATE)
                        .edit()
                        .putBoolean(AgentService.PREF_TCP_ENABLED, enabled)
                        .putInt(AgentService.PREF_TCP_PORT, port)
                        .apply()
                    AgentLog.add("UI", "TCP 设置: ${if (enabled) "开" else "关"} 端口 $port（重启 agent 生效）")
                    toast("已保存，重启 agent 生效")
                },
            )
            else -> LogsScreen(modifier = Modifier.padding(padding), logs = logs)
        }
    }
}

// ---------------------------------------------------------------- 密钥页

@Composable
private fun KeysScreen(
    modifier: Modifier,
    status: SvcStatus,
    keys: List<KeyVm>,
    busy: Boolean,
    onStart: () -> Unit,
    onGenerate: (String) -> Unit,
    onImport: (String) -> Unit,
    onCopy: (KeyVm) -> Unit,
    onDelete: (KeyVm) -> Unit,
    onTcpSave: (Boolean, Int) -> Unit,
) {
    var showGen by remember { mutableStateOf(false) }
    var showImp by remember { mutableStateOf(false) }
    var showTcp by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<KeyVm?>(null) }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { StatusCard(status, onStart = onStart, onTcp = { showTcp = true }) }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = { showGen = true },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Filled.Add, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("生成密钥")
                }
                FilledTonalButton(
                    onClick = { showImp = true },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Filled.FileDownload, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("导入私钥")
                }
            }
        }

        if (keys.isEmpty()) {
            item {
                Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors()) {
                    Column(Modifier.padding(20.dp)) {
                        Text("还没有密钥", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "生成一把新密钥，或从电脑粘贴已有的 OpenSSH 私钥导入。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        items(keys, key = { it.id }) { key ->
            KeyCard(
                key = key,
                onCopy = { onCopy(key) },
                onDelete = { pendingDelete = key },
            )
        }

        item { Spacer(Modifier.height(24.dp)) }
    }

    if (showGen) {
        GenerateDialog(
            onDismiss = { showGen = false },
            onConfirm = { c -> showGen = false; onGenerate(c) },
        )
    }
    if (showImp) {
        ImportDialog(
            onDismiss = { showImp = false },
            onConfirm = { pem -> showImp = false; onImport(pem) },
        )
    }
    if (showTcp) {
        TcpDialog(
            initialEnabled = status.tcpEnabled,
            initialPort = status.port,
            onDismiss = { showTcp = false },
            onConfirm = { e, p -> showTcp = false; onTcpSave(e, p) },
        )
    }
    pendingDelete?.let { k ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("删除密钥 ${k.comment.ifEmpty { k.id }}？") },
            text = { Text("删除后这把钥匙的密文随之消失，无法恢复。") },
            confirmButton = {
                TextButton(onClick = { pendingDelete = null; onDelete(k) }) { Text("删除") }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text("取消") }
            },
        )
    }
}

@Composable
private fun StatusCard(status: SvcStatus, onStart: () -> Unit, onTcp: () -> Unit) {
    val running = status.running
    val dotColor = if (running) Color(0xFF4CAF50) else MaterialTheme.colorScheme.outline
    val subColor = MaterialTheme.colorScheme.onSurfaceVariant
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(dotColor, CircleShape))
                Spacer(Modifier.width(8.dp))
                Text(
                    if (running) "SSH Agent 运行中" else "SSH Agent 未运行",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                if (running) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "已运行 " + fmtUptime(status.startedAt),
                        fontSize = 11.sp,
                        color = subColor,
                    )
                }
            }
            Spacer(Modifier.height(10.dp))
            Mono(
                "tcp       " + when {
                    status.running -> "0.0.0.0:${status.port}  ✓"
                    status.tcpEnabled -> "端口 ${status.port} 未监听"
                    else -> "未启用"
                }
            )
            Mono("discover  udp:" + AgentService.DISCOVERY_PORT + if (status.discoveryReady) "  ✓ 可被发现" else "  —")
            Mono("lan       " + lanIp() + ":" + status.port)
            Mono("keys      ${status.keyCount} 把")
            Mono("conns     ${status.activeConns} 活跃 · identities ${status.identitiesCalls} 次")
            Mono(
                "signs     ${status.totalSigns} 次" +
                        if (status.lastSignAt > 0) " · 最近 ${fmtTime(status.lastSignAt)} ${status.lastSignKey}" else ""
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onStart) {
                    Icon(Icons.Filled.PlayArrow, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (running) "重启服务" else "启动服务")
                }
                FilledTonalButton(onClick = onTcp) {
                    Icon(Icons.Filled.Settings, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("局域网")
                }
            }
        }
    }
}

/** 本机局域网 IPv4，用来告诉用户在电脑上连哪个地址 */
private fun lanIp(): String = try {
    java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())
        .filter { it.isUp && !it.isLoopback }
        .flatMap { it.interfaceAddresses }
        .mapNotNull { it.address }
        .firstOrNull { it is java.net.Inet4Address && it.isSiteLocalAddress }
        ?.hostAddress ?: "?"
} catch (t: Throwable) {
    "?"
}

private fun fmtTime(ts: Long): String =
    if (ts <= 0) "—"
    else java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date(ts))

private fun fmtUptime(startedAt: Long): String {
    if (startedAt <= 0) return "—"
    val s = (System.currentTimeMillis() - startedAt) / 1000
    val h = s / 3600
    val m = (s % 3600) / 60
    val sec = s % 60
    return when {
        h > 0 -> "${h}h${m}m"
        m > 0 -> "${m}m${sec}s"
        else -> "${sec}s"
    }
}

@Composable
private fun KeyCard(key: KeyVm, onCopy: () -> Unit, onDelete: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Key,
                    null,
                    Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    key.comment.ifEmpty { "(无 comment)" },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(6.dp))
            Mono(key.fingerprint)
            Spacer(Modifier.height(4.dp))
            SelectionContainer {
                Text(
                    key.pubLine,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(6.dp))
            Row {
                TextButton(onClick = onCopy) {
                    Icon(Icons.Filled.ContentCopy, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("复制公钥")
                }
                TextButton(onClick = onDelete) {
                    Icon(
                        Icons.Filled.Delete, null, Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("删除", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

// ---------------------------------------------------------------- 日志页

@Composable
private fun LogsScreen(modifier: Modifier, logs: List<String>) {
    val listState = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.lastIndex)
    }
    if (logs.isEmpty()) {
        Column(
            modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("暂无日志", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        return
    }
    LazyColumn(
        state = listState,
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        items(logs) { line ->
            SelectionContainer {
                Text(
                    line,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 15.sp,
                )
            }
        }
    }
}

// ---------------------------------------------------------------- 对话框

@Composable
private fun GenerateDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var comment by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("生成新密钥") },
        text = {
            Column {
                Text(
                    "comment 用来在电脑端认出这把钥匙，例如 dsh。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = comment,
                    onValueChange = { comment = it },
                    label = { Text("comment") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(comment.trim().ifEmpty { "android" }) }) {
                Text("生成")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

@Composable
private fun ImportDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var pem by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("导入私钥") },
        text = {
            Column {
                Text(
                    "粘贴未加密的 OpenSSH Ed25519 私钥。导入后立刻用指纹加密存入 Keystore，明文不保留。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = pem,
                    onValueChange = { pem = it },
                    label = { Text("-----BEGIN OPENSSH PRIVATE KEY-----") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    minLines = 6,
                    maxLines = 12,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(pem.trim()) }) { Text("导入") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

@Composable
private fun TcpDialog(
    initialEnabled: Boolean,
    initialPort: Int,
    onDismiss: () -> Unit,
    onConfirm: (Boolean, Int) -> Unit,
) {
    var enabled by remember { mutableStateOf(initialEnabled) }
    var port by remember { mutableStateOf(initialPort.toString()) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("局域网访问") },
        text = {
            Column {
                Text(
                    "开启后，同一局域网的电脑可以直接连这台手机的 agent。每次签名都要手机指纹，不需要白名单。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("启用 TCP", modifier = Modifier.weight(1f))
                    Switch(checked = enabled, onCheckedChange = { enabled = it })
                }
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it.filter(Char::isDigit) },
                    label = { Text("端口 (1024-65535)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val p = port.toIntOrNull()
                if (p != null && p in 1024..65535) onConfirm(enabled, p)
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

// ---------------------------------------------------------------- 工具

@Composable
private fun Mono(text: String) {
    Text(
        text,
        fontSize = 12.sp,
        fontFamily = FontFamily.Monospace,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** 指纹认证 → 返回已授权的 Cipher；取消/失败返回 null */
private suspend fun awaitBiometric(activity: Activity, title: String, cipher: Cipher): Cipher? =
    suspendCancellableCoroutine { cont ->
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            cont.resume(null)
            return@suspendCancellableCoroutine
        }
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(title)
            .setSubtitle("验证指纹")
            .setDescription("密钥在 TEE 内，认证通过后 Keystore 才放行本次加解密")
            .setNegativeButton("取消", activity.mainExecutor) { _, _ ->
                if (cont.isActive) cont.resume(null)
            }
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(cipher),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(result.cryptoObject?.cipher)
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    AgentLog.add("Bio", "auth error $code: $msg")
                    if (cont.isActive) cont.resume(null)
                }
            },
        )
    }

/** 指纹通过后把私钥加密存入 Keystore；任何一步失败返回 false */
private suspend fun saveKey(
    activity: Activity,
    pem: String,
    pubLine: String,
    pubBlob: ByteArray,
    comment: String,
): Boolean {
    return try {
        val prepared = withContext(Dispatchers.IO) {
            SshKeyVault.ensureKek(true, true)
            SshKeyVault.prepareSeal()
        }
        val cipher = if (prepared.alreadyAuthorized) {
            prepared.cipher
        } else {
            withContext(Dispatchers.Main) {
                awaitBiometric(activity, "加密保存私钥: $comment", prepared.cipher)
            } ?: return false
        }
        withContext(Dispatchers.IO) {
            val sealed = SshKeyVault.seal(cipher, pem.toByteArray(Charsets.UTF_8))
            SshKeyVault.addEntry(activity, comment, pubLine, pubBlob, sealed)
            AgentLog.add("UI", "已加密保存 $comment (${sealed.totalBytes()}B)")
        }
        true
    } catch (t: Throwable) {
        AgentLog.add("UI", "saveKey failed: $t")
        false
    }
}
