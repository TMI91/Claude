package com.example.lists.ui

import android.os.Bundle
import android.view.*
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.MenuProvider
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.RecyclerView
import com.example.lists.R
import com.example.lists.data.ListGroup
import com.example.lists.data.ListType
import com.example.lists.databinding.DialogAddListBinding
import com.example.lists.databinding.FragmentHomeBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder

class HomeFragment : Fragment() {
    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    private val vm: ListsViewModel by activityViewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        // Observe dynamic title
        vm.appTitle.observe(viewLifecycleOwner) { title ->
            (requireActivity() as AppCompatActivity).supportActionBar?.title = title
        }

        // Settings menu
        requireActivity().addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, inflater: MenuInflater) {
                inflater.inflate(R.menu.menu_home, menu)
            }
            override fun onMenuItemSelected(item: MenuItem): Boolean {
                if (item.itemId == R.id.action_settings) {
                    (activity as MainActivity).openSettings()
                    return true
                }
                return false
            }
        }, viewLifecycleOwner)

        val adapter = ListGroupAdapter(
            onClick = { group -> (activity as MainActivity).openList(group) },
            onLongClick = { group -> confirmDelete(group) }
        )
        binding.recycler.adapter = adapter

        // Swipe-to-delete lists
        ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            0, ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT
        ) {
            override fun onMove(rv: RecyclerView, vh: RecyclerView.ViewHolder,
                                target: RecyclerView.ViewHolder) = false
            override fun onSwiped(vh: RecyclerView.ViewHolder, direction: Int) {
                val group = adapter.getItemAt(vh.adapterPosition)
                // Put item back visually until confirmed
                adapter.notifyItemChanged(vh.adapterPosition)
                confirmDelete(group)
            }
        }).attachToRecyclerView(binding.recycler)

        vm.groups.observe(viewLifecycleOwner) { adapter.submitList(it) }

        binding.fab.setOnClickListener { showAddListDialog() }
    }

    private fun showAddListDialog() {
        val dialogBinding = DialogAddListBinding.inflate(layoutInflater)
        val types = ListType.values()
        val labels = types.map { it.name.lowercase().replaceFirstChar { c -> c.uppercase() } }
        dialogBinding.spinnerType.adapter =
            ArrayAdapter(requireContext(), android.R.layout.simple_spinner_dropdown_item, labels)

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.new_list)
            .setView(dialogBinding.root)
            .setPositiveButton(R.string.create) { _, _ ->
                val name = dialogBinding.etName.text?.toString()?.trim() ?: ""
                if (name.isNotEmpty()) {
                    val type = types[dialogBinding.spinnerType.selectedItemPosition]
                    vm.addGroup(name, type)
                }
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun confirmDelete(group: ListGroup) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.delete_list)
            .setMessage(getString(R.string.delete_list_confirm, group.name))
            .setPositiveButton(R.string.delete) { _, _ -> vm.deleteGroup(group) }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
