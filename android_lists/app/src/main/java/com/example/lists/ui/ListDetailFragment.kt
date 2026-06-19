package com.example.lists.ui

import android.os.Bundle
import android.view.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.MenuProvider
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.RecyclerView
import com.example.lists.R
import com.example.lists.data.SortOrder
import com.example.lists.databinding.FragmentListDetailBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder

class ListDetailFragment : Fragment() {
    private var _binding: FragmentListDetailBinding? = null
    private val binding get() = _binding!!
    private val vm: ListsViewModel by activityViewModels()
    private lateinit var itemAdapter: ListItemAdapter
    private var dragFrom = -1

    companion object {
        private const val ARG_GROUP_ID   = "group_id"
        private const val ARG_GROUP_NAME = "group_name"

        fun newInstance(groupId: Long, name: String) = ListDetailFragment().apply {
            arguments = Bundle().apply {
                putLong(ARG_GROUP_ID, groupId)
                putString(ARG_GROUP_NAME, name)
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentListDetailBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val groupId   = requireArguments().getLong(ARG_GROUP_ID)
        val groupName = requireArguments().getString(ARG_GROUP_NAME) ?: ""

        (requireActivity() as AppCompatActivity).supportActionBar?.title = groupName
        vm.setCurrentGroup(groupId)

        // Adapter — inline input at top, checkboxes always on
        itemAdapter = ListItemAdapter(
            onCheck   = { item -> vm.toggleItem(item) },
            onAddItem = { text -> vm.addItem(groupId, text) },
            onEdit    = { item -> showEditDialog(item) }
        )
        binding.recycler.adapter = itemAdapter

        // Swipe-to-delete + drag-to-reorder (position 0 = input row, skip it)
        val touchHelper = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            ItemTouchHelper.UP or ItemTouchHelper.DOWN,
            ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT
        ) {
            override fun getMovementFlags(rv: RecyclerView, vh: RecyclerView.ViewHolder): Int {
                if (vh is ListItemAdapter.InputVH) return 0  // input row: no touch
                val drag = if (vm.currentGroup.value?.sortOrder == SortOrder.MANUAL)
                    ItemTouchHelper.UP or ItemTouchHelper.DOWN else 0
                return makeMovementFlags(drag, ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT)
            }

            override fun onMove(
                rv: RecyclerView,
                vh: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ): Boolean {
                if (target is ListItemAdapter.InputVH) return false
                val from = vh.adapterPosition
                val to   = target.adapterPosition
                if (dragFrom == -1) dragFrom = from
                itemAdapter.isDragging = true
                itemAdapter.moveItemVisually(from, to)
                return true
            }

            override fun onSwiped(vh: RecyclerView.ViewHolder, direction: Int) {
                val pos  = vh.adapterPosition
                val item = itemAdapter.getItemAt(pos)
                itemAdapter.removeAt(pos)
                vm.deleteItem(item)
            }

            override fun clearView(rv: RecyclerView, vh: RecyclerView.ViewHolder) {
                super.clearView(rv, vh)
                if (dragFrom != -1) {
                    vm.saveItemPositions(itemAdapter.getCurrentItems())
                    dragFrom = -1
                }
                itemAdapter.isDragging = false
            }
        })
        touchHelper.attachToRecyclerView(binding.recycler)

        vm.sortedItems.observe(viewLifecycleOwner) { items -> itemAdapter.setItems(items) }

        // Sort menu in toolbar
        requireActivity().addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, inflater: MenuInflater) {
                inflater.inflate(R.menu.menu_list_detail, menu)
            }
            override fun onMenuItemSelected(item: MenuItem): Boolean {
                return when (item.itemId) {
                    R.id.action_sort -> { showSortDialog(); true }
                    R.id.action_delete_checked -> { confirmDeleteChecked(); true }
                    else -> false
                }
            }
        }, viewLifecycleOwner)
    }

    private fun showEditDialog(item: com.example.lists.data.ListItem) {
        val input = com.google.android.material.textfield.TextInputEditText(requireContext())
        val layout = com.google.android.material.textfield.TextInputLayout(requireContext()).apply {
            hint = getString(R.string.item_text)
            addView(input)
            setPadding(48, 16, 48, 0)
        }
        input.setText(item.text)
        input.setSelection(item.text.length)

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.edit_item)
            .setView(layout)
            .setPositiveButton(R.string.save) { _, _ ->
                val newText = input.text?.toString()?.trim() ?: ""
                if (newText.isNotEmpty()) vm.editItem(item, newText)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteChecked() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.delete_checked)
            .setMessage(R.string.delete_checked_confirm)
            .setPositiveButton(R.string.delete) { _, _ -> vm.deleteCheckedItems() }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun showSortDialog() {
        val orders  = SortOrder.values()
        val labels  = arrayOf("A → Z", "Z → A", "Oldest first", "Newest first", "Manual order")
        val current = vm.currentGroup.value?.sortOrder ?: SortOrder.DATE_DESC

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.sort_by)
            .setSingleChoiceItems(labels, orders.indexOf(current)) { dialog, which ->
                vm.updateGroupSort(orders[which])
                dialog.dismiss()
            }
            .show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
