package com.example.lists.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface ListItemDao {
    @Query("SELECT * FROM list_items WHERE groupId = :groupId")
    fun getItemsForGroup(groupId: Long): Flow<List<ListItem>>

    @Query("SELECT COALESCE(MAX(position), -1) FROM list_items WHERE groupId = :groupId")
    suspend fun maxPosition(groupId: Long): Int

    @Insert
    suspend fun insert(item: ListItem)

    @Update
    suspend fun update(item: ListItem)

    @Delete
    suspend fun delete(item: ListItem)

    @Query("UPDATE list_items SET position = :position WHERE id = :id")
    suspend fun updatePosition(id: Long, position: Int)

    @Query("DELETE FROM list_items WHERE groupId = :groupId AND isChecked = 1")
    suspend fun deleteChecked(groupId: Long)

    @Query("SELECT * FROM list_items WHERE groupId = :groupId")
    suspend fun getItemsForGroupSync(groupId: Long): List<ListItem>

    @Insert(onConflict = androidx.room.OnConflictStrategy.REPLACE)
    suspend fun insertAll(items: List<ListItem>)

    @Query("DELETE FROM list_items")
    suspend fun deleteAll()
}
