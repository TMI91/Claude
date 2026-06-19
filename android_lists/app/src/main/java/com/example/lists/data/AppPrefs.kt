package com.example.lists.data

import android.content.Context

class AppPrefs(context: Context) {
    private val prefs = context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)

    var syncFolderUri: String?
        get() = prefs.getString(KEY_SYNC_URI, null)
        set(v) { prefs.edit().putString(KEY_SYNC_URI, v).apply() }

    var appTitle: String
        get() = prefs.getString(KEY_TITLE, DEFAULT_TITLE) ?: DEFAULT_TITLE
        set(v) { prefs.edit().putString(KEY_TITLE, v).apply() }

    /** Timestamp of the last export we did, so we can detect a newer file from another device. */
    var lastExportAt: Long
        get() = prefs.getLong(KEY_LAST_EXPORT, 0L)
        set(v) { prefs.edit().putLong(KEY_LAST_EXPORT, v).apply() }

    var syncEnabled: Boolean
        get() = prefs.getBoolean(KEY_SYNC_ENABLED, false)
        set(v) { prefs.edit().putBoolean(KEY_SYNC_ENABLED, v).apply() }

    companion object {
        private const val KEY_SYNC_URI     = "sync_folder_uri"
        private const val KEY_TITLE        = "app_title"
        private const val KEY_LAST_EXPORT  = "last_export_at"
        private const val KEY_SYNC_ENABLED = "sync_enabled"
        const val DEFAULT_TITLE            = "My Lists"
    }
}
