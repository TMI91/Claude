package com.example.lists.ui

import android.graphics.Paint
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import androidx.recyclerview.widget.RecyclerView
import com.example.lists.data.ListItem
import com.example.lists.databinding.ItemListItemBinding
import com.example.lists.databinding.ItemNewItemBinding

class ListItemAdapter(
    private val onCheck: (ListItem) -> Unit,
    var onAddItem: ((String) -> Unit)? = null,
    var onEdit: ((ListItem) -> Unit)? = null
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    private val items = mutableListOf<ListItem>()
    var isDragging = false

    companion object {
        private const val TYPE_INPUT = 0
        private const val TYPE_ITEM  = 1
    }

    // ── public API ──────────────────────────────────────────────

    fun setItems(newItems: List<ListItem>) {
        if (isDragging) return
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }

    fun getItemAt(adapterPos: Int): ListItem = items[adapterPos - 1]
    fun getCurrentItems(): List<ListItem> = items.toList()

    fun moveItemVisually(from: Int, to: Int) {
        val item = items.removeAt(from - 1)
        items.add(to - 1, item)
        notifyItemMoved(from, to)
    }

    fun removeAt(adapterPos: Int) {
        items.removeAt(adapterPos - 1)
        notifyItemRemoved(adapterPos)
    }

    // ── view types ───────────────────────────────────────────────

    override fun getItemViewType(position: Int) = if (position == 0) TYPE_INPUT else TYPE_ITEM
    override fun getItemCount() = items.size + 1   // +1 for the input row

    // ── ViewHolders ──────────────────────────────────────────────

    inner class InputVH(val binding: ItemNewItemBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind() {
            binding.etNewItem.setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    val text = binding.etNewItem.text?.toString()?.trim() ?: ""
                    if (text.isNotEmpty()) {
                        onAddItem?.invoke(text)
                        binding.etNewItem.text?.clear()
                    }
                    true
                } else false
            }
        }
    }

    inner class ItemVH(val binding: ItemListItemBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(item: ListItem) {
            binding.tvText.text = item.text

            binding.checkbox.setOnCheckedChangeListener(null)
            binding.checkbox.isChecked = item.isChecked
            binding.checkbox.setOnCheckedChangeListener { _, _ -> onCheck(item) }

            binding.tvText.paintFlags = if (item.isChecked) {
                binding.tvText.paintFlags or Paint.STRIKE_THRU_TEXT_FLAG
            } else {
                binding.tvText.paintFlags and Paint.STRIKE_THRU_TEXT_FLAG.inv()
            }

            // Dim checked items slightly
            binding.root.alpha = if (item.isChecked) 0.5f else 1.0f

            // Tap text to edit
            binding.tvText.setOnClickListener { onEdit?.invoke(item) }
        }
    }

    // ── RecyclerView.Adapter ─────────────────────────────────────

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return if (viewType == TYPE_INPUT)
            InputVH(ItemNewItemBinding.inflate(inflater, parent, false))
        else
            ItemVH(ItemListItemBinding.inflate(inflater, parent, false))
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (holder) {
            is InputVH -> holder.bind()
            is ItemVH  -> holder.bind(items[position - 1])
        }
    }
}
