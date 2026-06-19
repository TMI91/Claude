package com.example.lists.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.example.lists.R
import com.example.lists.data.ListGroup
import com.example.lists.data.ListType
import com.example.lists.databinding.ItemListGroupBinding

class ListGroupAdapter(
    private val onClick: (ListGroup) -> Unit,
    private val onLongClick: (ListGroup) -> Unit
) : RecyclerView.Adapter<ListGroupAdapter.VH>() {

    private val items = mutableListOf<ListGroup>()

    fun getItemAt(position: Int): ListGroup = items[position]

    fun submitList(newItems: List<ListGroup>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }

    inner class VH(val binding: ItemListGroupBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemListGroupBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val group = items[position]
        holder.binding.tvName.text = group.name
        holder.binding.tvType.text = group.type.name
            .lowercase()
            .replaceFirstChar { it.uppercase() }

        val colorRes = when (group.type) {
            ListType.TODO     -> R.color.type_todo
            ListType.SHOPPING -> R.color.type_shopping
            ListType.NOTES    -> R.color.type_notes
            ListType.OTHER    -> R.color.type_other
        }
        holder.binding.typeIndicator.setBackgroundColor(
            holder.itemView.context.getColor(colorRes)
        )

        holder.binding.root.setOnClickListener { onClick(group) }
        holder.binding.root.setOnLongClickListener { onLongClick(group); true }
    }
}
