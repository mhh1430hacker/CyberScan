package io.github.mhh1430hacker.cyberscan

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.util.concurrent.Executors

/**
 * The Android side of three features, over one MethodChannel ("cyberscan/native"):
 *
 *  1. Share to CyberScan: files, links and text shared from other apps (ACTION_SEND /
 *     ACTION_SEND_MULTIPLE, see AndroidManifest.xml). Shared files are copied into the app's
 *     private cache (the sharing app's permission is temporary) and handed to Dart as paths.
 *  2. The home-screen widget (ScanWidgetProvider): Dart sends the latest result; the widget's
 *     "Quick scan" button opens the app with ACTION_QUICK_SCAN.
 *  3. New files in a folder the user granted once through the Storage Access Framework. No
 *     storage permission is requested: Android hands out access to that one folder only.
 *
 * Nothing here touches the network.
 */
class MainActivity : FlutterActivity() {
    companion object {
        const val CHANNEL = "cyberscan/native"
        const val ACTION_QUICK_SCAN = "io.github.mhh1430hacker.cyberscan.QUICK_SCAN"
        const val MAX_FILE = 100L shl 20   // same limit as the in-app picker
        const val MAX_FILES = 20
        private const val PICK_FOLDER = 4711
        private const val PREFS = "cyberscan_native"
    }

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var channel: MethodChannel? = null
    private var pending: Map<String, Any?>? = null      // a share / quick scan waiting for Dart
    private var dartReady = false
    private var folderResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).also {
            it.setMethodCallHandler { call, result -> handle(call, result) }
        }
        intent?.let { capture(it) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        capture(intent)
    }

    // ------------------------------------------------------------------ incoming intents
    private fun capture(intent: Intent) {
        when (intent.action) {
            ACTION_QUICK_SCAN -> deliver(mapOf("type" to "quickScan"))
            Intent.ACTION_SEND, Intent.ACTION_SEND_MULTIPLE -> {
                val uris = sharedUris(intent)
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                val subject = intent.getStringExtra(Intent.EXTRA_SUBJECT)
                // consume it, so a rotation or relaunch does not scan the same share twice
                intent.action = Intent.ACTION_MAIN
                if (uris.isEmpty()) {
                    if (!text.isNullOrBlank()) deliver(mapOf("type" to "text", "text" to text, "subject" to subject))
                    return
                }
                io.execute {
                    val files = uris.take(MAX_FILES).mapNotNull { copyToCache(it) }
                    main.post {
                        deliver(mapOf("type" to "files", "files" to files, "text" to text, "skipped" to (uris.size - files.size)))
                    }
                }
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun sharedUris(intent: Intent): List<Uri> {
        val out = mutableListOf<Uri>()
        if (intent.action == Intent.ACTION_SEND_MULTIPLE) {
            val list: List<Uri>? = if (Build.VERSION.SDK_INT >= 33)
                intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
            else intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
            list?.let { out.addAll(it) }
        } else {
            val one: Uri? = if (Build.VERSION.SDK_INT >= 33)
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            else intent.getParcelableExtra(Intent.EXTRA_STREAM)
            one?.let { out.add(it) }
        }
        if (out.isEmpty()) intent.clipData?.let { clip -> for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let { out.add(it) } }
        return out.filter { it.scheme == "content" || it.scheme == "file" }
    }

    private fun deliver(event: Map<String, Any?>) {
        if (dartReady) channel?.invokeMethod("incoming", event) else pending = event
    }

    /** Copies a shared document into cache/shared/ and describes it; null when unreadable or too big. */
    private fun copyToCache(uri: Uri): Map<String, Any?>? = try {
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "shared-file"
        var size = -1L
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                c.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 }?.let { i -> c.getString(i)?.let { name = it } }
                c.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 && !c.isNull(it) }?.let { i -> size = c.getLong(i) }
            }
        }
        if (size > MAX_FILE) {
            mapOf("name" to name, "path" to null, "size" to size, "tooBig" to true)
        } else {
            val dir = File(cacheDir, "shared").apply { mkdirs() }
            val target = File(dir, "${System.nanoTime()}-${name.replace(Regex("[\\\\/:*?\"<>|]"), "_").take(120)}")
            var copied = 0L
            contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        copied += n
                        if (copied > MAX_FILE) throw IllegalStateException("too big")
                        out.write(buf, 0, n)
                    }
                }
            } ?: throw IllegalStateException("unreadable")
            mapOf("name" to name, "path" to target.absolutePath, "size" to copied, "tooBig" to false)
        }
    } catch (e: Exception) {
        null
    }

    // ------------------------------------------------------------------ calls from Dart
    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "ready" -> {   // Dart is listening: hand over what arrived before it started
                dartReady = true
                val p = pending
                pending = null
                result.success(p)
            }
            "updateWidget" -> {
                ScanWidgetProvider.save(this, call.argument<String>("verdict") ?: "", call.argument<String>("label") ?: "",
                    call.argument<String>("target") ?: "", call.argument<Int>("score") ?: 0, call.argument<String>("when") ?: "",
                    call.argument<String>("button") ?: "Quick scan", call.argument<String>("empty") ?: "")
                result.success(true)
            }
            "clearShared" -> { io.execute { File(cacheDir, "shared").listFiles()?.forEach { it.delete() } }; result.success(true) }
            "pickFolder" -> {
                folderResult?.success(null)
                folderResult = result
                val i = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
                try { startActivityForResult(i, PICK_FOLDER) } catch (e: Exception) { folderResult = null; result.success(null) }
            }
            "folder" -> result.success(folderInfo())
            "forgetFolder" -> {
                prefs().getString("tree", null)?.let { t ->
                    try { contentResolver.releasePersistableUriPermission(Uri.parse(t), Intent.FLAG_GRANT_READ_URI_PERMISSION) } catch (_: Exception) {}
                }
                prefs().edit().remove("tree").remove("treeName").apply()
                result.success(true)
            }
            "listFolder" -> {
                val tree = prefs().getString("tree", null)
                if (tree == null) { result.success(null); return }
                io.execute {
                    val list = try { listTree(Uri.parse(tree)) } catch (e: Exception) { null }
                    main.post { result.success(list) }
                }
            }
            "copyDocument" -> {
                val uri = call.argument<String>("uri")
                if (uri == null) { result.success(null); return }
                io.execute {
                    val f = copyToCache(Uri.parse(uri))
                    main.post { result.success(f) }
                }
            }
            else -> result.notImplemented()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK_FOLDER) return
        val r = folderResult ?: return
        folderResult = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) { r.success(null); return }
        try {
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: Exception) {}
        val name = try {
            DocumentsContract.getTreeDocumentId(uri).substringAfterLast(':').ifEmpty { "Download" }
        } catch (_: Exception) { "folder" }
        prefs().edit().putString("tree", uri.toString()).putString("treeName", name).apply()
        r.success(folderInfo())
    }

    private fun prefs() = getSharedPreferences(PREFS, MODE_PRIVATE)

    private fun folderInfo(): Map<String, Any?>? {
        val t = prefs().getString("tree", null) ?: return null
        val still = contentResolver.persistedUriPermissions.any { it.uri.toString() == t && it.isReadPermission }
        return mapOf("uri" to t, "name" to prefs().getString("treeName", "folder"), "granted" to still)
    }

    /** Files directly inside the granted folder (not sub-folders), newest first. */
    private fun listTree(tree: Uri): List<Map<String, Any?>> {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        val cols = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_SIZE, DocumentsContract.Document.COLUMN_LAST_MODIFIED, DocumentsContract.Document.COLUMN_MIME_TYPE)
        val out = mutableListOf<Map<String, Any?>>()
        contentResolver.query(children, cols, null, null, null)?.use { c ->
            while (c.moveToNext()) {
                val mime = c.getString(4) ?: ""
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                out.add(mapOf(
                    "uri" to DocumentsContract.buildDocumentUriUsingTree(tree, c.getString(0)).toString(),
                    "name" to (c.getString(1) ?: "file"),
                    "size" to (if (c.isNull(2)) -1L else c.getLong(2)),
                    "modified" to (if (c.isNull(3)) 0L else c.getLong(3)),
                ))
            }
        }
        return out.sortedByDescending { it["modified"] as Long }.take(500)
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }
}
