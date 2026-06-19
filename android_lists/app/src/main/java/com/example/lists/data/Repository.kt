package com.example.lists.data

import kotlinx.coroutines.flow.Flow

class Repository(private val db: AppDatabase) {
    fun getGroups(): Flow<List<ListGroup>> = db.listGroupDao().getAll()
    fun getItems(groupId: Long): Flow<List<ListItem>> = db.listItemDao().getItemsForGroup(groupId)

    suspend fun addGroup(group: ListGroup) = db.listGroupDao().insert(group)
    suspend fun updateGroup(group: ListGroup) = db.listGroupDao().update(group)
    suspend fun deleteGroup(group: ListGroup) = db.listGroupDao().delete(group)

    suspend fun addItem(groupId: Long, text: String) {
        val pos = db.listItemDao().maxPosition(groupId) + 1
        db.listItemDao().insert(ListItem(groupId = groupId, text = text, position = pos))
    }

    suspend fun updateItem(item: ListItem) = db.listItemDao().update(item)
    suspend fun deleteItem(item: ListItem) = db.listItemDao().delete(item)

    suspend fun deleteCheckedItems(groupId: Long) = db.listItemDao().deleteChecked(groupId)

    suspend fun saveItemPositions(items: List<ListItem>) {
        items.forEachIndexed { index, item ->
            db.listItemDao().updatePosition(item.id, index)
        }
    }
}
