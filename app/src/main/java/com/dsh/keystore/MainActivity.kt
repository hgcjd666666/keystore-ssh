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
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
 * 密钥管理界面。
 *
 * 这个 App 是「空壳」：只负责 Keystore 里的私钥和指纹授权，不跑网络服务。
 * TCP agent 在 root 侧（app_process / C），它用 am start 拉起 SignActivity 来签名。
 *
 *   · 密钥页：列表 / 生成 / 导入 / 删除 / 复制公钥
 *   · 日志页：签名与错误记录
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
    }
}

data class KeyVm(
    val id: String,
    val comment: String,
    val fingerprint: String,
    val pubLine: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(activity: Activity) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var tab by rememberSaveable { mutableIntStateOf(0) }
    var keys by remember { mutableStateOf<List<KeyVm>>(emptyList()) }
    var logs by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }

    suspend fun refresh() {
        val app = ctx.applicationContext
        withContext(Dispatchers.IO) {
            keys = SshKeyVault.listEntries(app).map {
                KeyVm(it.id, it.comment, it.fingerprint(), it.pubLine)
            }
        }
        logs = AgentLog.snapshot()
    }

    LaunchedEffect(Unit) {
        while (isActive) {
            try {
                refresh()
            } catch (t: Throwable) {
                AgentLog.add("UI", "refresh failed: $t")
            }
            delay(1000)
        }
    }

    fun toast(s: String) = Toast.makeText(activity, s, Toast.LENGTH_SHORT).show()

    fun copyPublic(key: KeyVm) {
        val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("ssh public key", key.pubLine))
        toast("公钥已复制")
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
                AgentLog.add("UI", if (ok) "已生成 $comment (${res.algo})" else "生成取消")
                if (ok) toast("已保存 $comment")
                if (ok) refresh()
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
                    AgentLog.add("UI", "导入跳过：公钥已存在")
                    toast("这把钥匙已经导入过了")
                    return@launch
                }
                val ok = saveKey(activity, pem, pubLine, blob, comment)
                AgentLog.add("UI", if (ok) "已导入 $comment" else "导入取消")
                if (ok) toast("已导入 $comment")
                if (ok) refresh()
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
                title = { Text("KeystoreSSH", fontWeight = FontWeight.SemiBold) }
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
                keys = keys,
                busy = busy,
                onGenerate = ::generate,
                onImport = ::import,
                onCopy = ::copyPublic,
                onDelete = ::delete,
            )
            else -> LogsScreen(modifier = Modifier.padding(padding), logs = logs)
        }
    }
}

// ---------------------------------------------------------------- 密钥页

@Composable
private fun KeysScreen(
    modifier: Modifier,
    keys: List<KeyVm>,
    busy: Boolean,
    onGenerate: (String) -> Unit,
    onImport: (String) -> Unit,
    onCopy: (KeyVm) -> Unit,
    onDelete: (KeyVm) -> Unit,
) {
    var showGen by remember { mutableStateOf(false) }
    var showImp by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<KeyVm?>(null) }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(18.dp)) {
                    Text(
                        "私钥由本机 Keystore 保护，签名时需指纹。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "局域网 agent 在 root 侧运行，通过系统调用本页的签名通道。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

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
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(20.dp)) {
                        Text("还没有密钥", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "生成一把新密钥，或粘贴已有的 OpenSSH Ed25519 私钥导入。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        items(keys, key = { it.id }) { key ->
            KeyCard(key = key, onCopy = { onCopy(key) }, onDelete = { pendingDelete = key })
        }

        item { Spacer(Modifier.height(24.dp)) }
    }

    if (showGen) {
        GenerateDialog({ showGen = false }) { c -> showGen = false; onGenerate(c) }
    }
    if (showImp) {
        ImportDialog({ showImp = false }) { pem -> showImp = false; onImport(pem) }
    }
    pendingDelete?.let { k ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("删除密钥 ${k.comment.ifEmpty { k.id }}？") },
            text = { Text("删除后这把钥匙的密文随之消失，无法恢复。") },
            confirmButton = {
                TextButton(onClick = { pendingDelete = null; onDelete(k) }) { Text("删除") }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("取消") } },
        )
    }
}

@Composable
private fun KeyCard(key: KeyVm, onCopy: () -> Unit, onDelete: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Key, null, Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Text(
                    key.comment.ifEmpty { "(无 comment)" },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                key.fingerprint,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
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
                    Icon(Icons.Filled.Delete, null, Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.error)
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
            TextButton(onClick = { onConfirm(comment.trim().ifEmpty { "android" }) }) { Text("生成") }
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

// ---------------------------------------------------------------- 工具

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
