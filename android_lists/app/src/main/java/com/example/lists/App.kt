package com.example.lists

import android.app.Application
import com.example.lists.data.AppDatabase

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // Open the SQLite connection on a background thread before the ViewModel needs it,
        // so the main thread is never blocked waiting on Room.build() + disk I/O at startup.
        Thread {
            val db = AppDatabase.get(this)
            db.listGroupDao()   // triggers actual connection open
        }.start()
    }
}
