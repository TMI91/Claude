package com.example.lists.data

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class SyncManager(private val context: Context, private val db: AppDatabase) {

    private val prefs = AppPrefs(context)
    private val FILENAME = "mylists.json"

    // ── Export ────────────────────────────────────────────────────

    val isActive: Boolean get() = prefs.syncEnabled && prefs.syncFolderUri != null

    suspend fun exportIfConfigured() {
        if (isActive) export()
    }

    suspend fun export() = withContext(Dispatchers.IO) {
        val uriStr = prefs.syncFolderUri ?: return@withContext
        try {
            val folder = DocumentFile.fromTreeUri(context, Uri.parse(uriStr)) ?: return@withContext
            val file = folder.findFile(FILENAME)
                ?: folder.createFile("application/json", FILENAME)
                ?: return@withContext

            val groups = db.listGroupDao().getAllSync()
            val root   = JSONObject()
            root.put("version", 1)
            root.put("exportedAt", System.currentTimeMillis())

            val listsArr = JSONArray()
            for (g in groups) {
                val gObj = JSONObject().apply {
                    put("id",        g.id)
                    put("name",      g.name)
                    put("type",      g.type.name)
                    put("sortOrder", g.sortOrder.name)
                    put("createdAt", g.createdAt)
                }
                val itemsArr = JSONArray()
                for (item in db.listItemDao().getItemsForGroupSync(g.id)) {
                    itemsArr.put(JSONObject().apply {
                        put("id",        item.id)
                        put("groupId",   item.groupId)
                        put("text",      item.text)
                        put("isChecked", item.isChecked)
                        put("position",  item.position)
                        put("createdAt", item.createdAt)
                    })
                }
                gObj.put("items", itemsArr)
                listsArr.put(gObj)
            }
            root.put("lists", listsArr)

            context.contentResolver.openOutputStream(file.uri, "wt")?.use { os ->
                os.writer().use { w -> w.write(root.toString(2)) }
            }
            prefs.lastExportAt = System.currentTimeMillis()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    // ── Import ────────────────────────────────────────────────────

    /** Returns true if a newer file was found and imported. */
    suspend fun importIfNewerOnDisk(): Boolean = withContext(Dispatchers.IO) {
        if (!isActive) return@withContext false
        val uriStr = prefs.syncFolderUri ?: return@withContext false
        try {
            val folder   = DocumentFile.fromTreeUri(context, Uri.parse(uriStr)) ?: return@withContext false
            val file     = folder.findFile(FILENAME) ?: return@withContext false
            if (file.lastModified() <= prefs.lastExportAt) return@withContext false
            importFromUri(file.uri)
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    suspend fun importFromUri(uri: Uri) = withContext(Dispatchers.IO) {
        try {
            val json = context.contentResolver.openInputStream(uri)?.use {
                it.reader().readText()
            } ?: return@withContext

            val root     = JSONObject(json)
            val listsArr = root.getJSONArray("lists")

            val groups = mutableListOf<ListGroup>()
            val items  = mutableListOf<ListItem>()

            for (i in 0 until listsArr.length()) {
                val g = listsArr.getJSONObject(i)
                groups.add(ListGroup(
                    id        = g.getLong("id"),
                    name      = g.getString("name"),
                    type      = ListType.valueOf(g.getString("type")),
                    sortOrder = SortOrder.valueOf(g.getString("sortOrder")),
                    createdAt = g.getLong("createdAt")
                ))
                val iArr = g.getJSONArray("items")
                for (j in 0 until iArr.length()) {
                    val it = iArr.getJSONObject(j)
                    items.add(ListItem(
                        id        = it.getLong("id"),
                        groupId   = it.getLong("groupId"),
                        text      = it.getString("text"),
                        isChecked = it.getBoolean("isChecked"),
                        position  = it.getInt("position"),
                        createdAt = it.getLong("createdAt")
                    ))
                }
            }

            // Replace local data
            db.listItemDao().deleteAll()
            db.listGroupDao().deleteAll()
            db.listGroupDao().insertAll(groups)
            db.listItemDao().insertAll(items)
            prefs.lastExportAt = System.currentTimeMillis()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
