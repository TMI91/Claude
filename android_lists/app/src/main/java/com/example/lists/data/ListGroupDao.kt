package com.example.lists.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface ListGroupDao {
    @Query("SELECT * FROM list_groups ORDER BY type ASC, name ASC")
    fun getAll(): Flow<List<ListGroup>>

    @Insert
    suspend fun insert(group: ListGroup): Long

    @Update
    suspend fun update(group: ListGroup)

    @Delete
    suspend fun delete(group: ListGroup)

    @Query("SELECT * FROM list_groups ORDER BY type ASC, name ASC")
    suspend fun getAllSync(): List<ListGroup>

    @Insert(onConflict = androidx.room.OnConflictStrategy.REPLACE)
    suspend fun insertAll(groups: List<ListGroup>)

    @Query("DELETE FROM list_groups")
    suspend fun deleteAll()
}
