package com.example.lists.ui

import android.app.Application
import androidx.lifecycle.*
import com.example.lists.data.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class ListsViewModel(app: Application) : AndroidViewModel(app) {
    private val db    by lazy { AppDatabase.get(app) }
    private val repo  by lazy { Repository(db) }
    private val sync  by lazy { SyncManager(app, db) }
    private val prefs = AppPrefs(app)

    // ── App title (observable so toolbar updates immediately) ─────
    private val _appTitle = MutableLiveData(prefs.appTitle)
    val appTitle: LiveData<String> = _appTitle

    fun setAppTitle(title: String) {
        prefs.appTitle = title
        _appTitle.value = title
    }

    // ── Lists ─────────────────────────────────────────────────────
    val groups: LiveData<List<ListGroup>> = repo.getGroups().asLiveData()

    private val _currentGroupId = MutableStateFlow(0L)

    val currentGroup: LiveData<ListGroup?> = _currentGroupId
        .flatMapLatest { id -> repo.getGroups().map { list -> list.find { it.id == id } } }
        .asLiveData()

    val sortedItems: LiveData<List<ListItem>> = _currentGroupId
        .flatMapLatest { id ->
            if (id == 0L) flowOf(emptyList())
            else combine(
                repo.getItems(id),
                repo.getGroups().map { list -> list.find { it.id == id } }
            ) { items, group -> applySorting(items, group?.sortOrder ?: SortOrder.DATE_DESC) }
        }
        .asLiveData()

    private fun applySorting(items: List<ListItem>, order: SortOrder): List<ListItem> {
        val open   = items.filter { !it.isChecked }
        val closed = items.filter {  it.isChecked }
        fun sortGroup(list: List<ListItem>) = when (order) {
            SortOrder.ALPHA_ASC  -> list.sortedBy { it.text.lowercase() }
            SortOrder.ALPHA_DESC -> list.sortedByDescending { it.text.lowercase() }
            SortOrder.DATE_ASC   -> list.sortedBy { it.createdAt }
            SortOrder.DATE_DESC  -> list.sortedByDescending { it.createdAt }
            SortOrder.MANUAL     -> list.sortedBy { it.position }
        }
        return sortGroup(open) + sortGroup(closed)
    }

    // ── Sync ──────────────────────────────────────────────────────
    init {
        // On startup, import from disk if another device wrote a newer file
        viewModelScope.launch { sync.importIfNewerOnDisk() }
    }

    fun triggerSync() = viewModelScope.launch { sync.export() }

    // ── Mutations (each triggers an auto-sync) ────────────────────
    fun setCurrentGroup(id: Long) { _currentGroupId.value = id }

    fun addGroup(name: String, type: ListType) = viewModelScope.launch {
        repo.addGroup(ListGroup(name = name, type = type))
        sync.exportIfConfigured()
    }

    fun updateGroupSort(order: SortOrder) = viewModelScope.launch {
        currentGroup.value?.let { repo.updateGroup(it.copy(sortOrder = order)) }
        sync.exportIfConfigured()
    }

    fun deleteGroup(group: ListGroup) = viewModelScope.launch {
        repo.deleteGroup(group)
        sync.exportIfConfigured()
    }

    fun addItem(groupId: Long, text: String) = viewModelScope.launch {
        repo.addItem(groupId, text)
        sync.exportIfConfigured()
    }

    fun editItem(item: ListItem, newText: String) = viewModelScope.launch {
        repo.updateItem(item.copy(text = newText))
        sync.exportIfConfigured()
    }

    fun toggleItem(item: ListItem) = viewModelScope.launch {
        repo.updateItem(item.copy(isChecked = !item.isChecked))
        sync.exportIfConfigured()
    }

    fun deleteItem(item: ListItem) = viewModelScope.launch {
        repo.deleteItem(item)
        sync.exportIfConfigured()
    }

    fun deleteCheckedItems() = viewModelScope.launch {
        repo.deleteCheckedItems(_currentGroupId.value)
        sync.exportIfConfigured()
    }

    fun saveItemPositions(items: List<ListItem>) = viewModelScope.launch {
        repo.saveItemPositions(items)
        sync.exportIfConfigured()
    }
}
