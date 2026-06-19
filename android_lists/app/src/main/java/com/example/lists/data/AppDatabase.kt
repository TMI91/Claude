package com.example.lists.data

import android.content.Context
import androidx.room.*

class Converters {
    @TypeConverter fun fromListType(v: ListType): String = v.name
    @TypeConverter fun toListType(v: String): ListType = ListType.valueOf(v)
    @TypeConverter fun fromSortOrder(v: SortOrder): String = v.name
    @TypeConverter fun toSortOrder(v: String): SortOrder = SortOrder.valueOf(v)
}

@Database(entities = [ListGroup::class, ListItem::class], version = 1, exportSchema = false)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun listGroupDao(): ListGroupDao
    abstract fun listItemDao(): ListItemDao

    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null

        fun get(context: Context): AppDatabase = INSTANCE ?: synchronized(this) {
            INSTANCE ?: Room.databaseBuilder(
                context.applicationContext, AppDatabase::class.java, "lists.db"
            ).build().also { INSTANCE = it }
        }
    }
}
