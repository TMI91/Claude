package com.example.lists.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "list_groups")
data class ListGroup(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val type: ListType,
    val sortOrder: SortOrder = SortOrder.DATE_DESC,
    val createdAt: Long = System.currentTimeMillis()
)
