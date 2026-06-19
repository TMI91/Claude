package com.example.lists.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.*
import android.view.inputmethod.EditorInfo
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.documentfile.provider.DocumentFile
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import com.example.lists.R
import com.example.lists.data.AppDatabase
import com.example.lists.data.AppPrefs
import com.example.lists.data.SyncManager
import com.example.lists.databinding.FragmentSettingsBinding
import kotlinx.coroutines.*

class SettingsFragment : Fragment() {
    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!
    private val vm: ListsViewModel by activityViewModels()
    private lateinit var prefs: AppPrefs
    private lateinit var syncManager: SyncManager
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private val folderPicker = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        requireContext().contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        )
        prefs.syncFolderUri = uri.toString()
        updateFolderDisplay()
        scope.launch {
            syncManager.export()
            showStatus(getString(R.string.sync_exported))
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        (requireActivity() as AppCompatActivity).supportActionBar?.title =
            getString(R.string.settings)

        prefs       = AppPrefs(requireContext())
        syncManager = SyncManager(requireContext(), AppDatabase.get(requireContext()))

        // App title
        binding.etAppTitle.setText(prefs.appTitle)
        binding.etAppTitle.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) saveTitle()
            true
        }
        binding.etAppTitle.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveTitle()
        }

        // Sync enable/disable toggle
        binding.switchSync.isChecked = prefs.syncEnabled
        updateSyncModeLabel()
        binding.switchSync.setOnCheckedChangeListener { _, isChecked ->
            prefs.syncEnabled = isChecked
            updateSyncModeLabel()
            updateFolderDisplay()
            if (isChecked && prefs.syncFolderUri != null) {
                // Switching ON: export current data immediately
                scope.launch {
                    syncManager.export()
                    showStatus(getString(R.string.sync_exported))
                }
            }
        }

        // Sync folder
        updateFolderDisplay()
        binding.btnChooseFolder.setOnClickListener { folderPicker.launch(null) }

        binding.btnClearFolder.setOnClickListener {
            prefs.syncFolderUri = null
            prefs.lastExportAt  = 0L
            updateFolderDisplay()
            showStatus(getString(R.string.sync_cleared))
        }

        binding.btnSyncNow.setOnClickListener {
            scope.launch {
                binding.btnSyncNow.isEnabled = false
                syncManager.export()
                binding.btnSyncNow.isEnabled = true
                showStatus(getString(R.string.sync_exported))
            }
        }

        binding.btnImportNow.setOnClickListener {
            scope.launch {
                binding.btnImportNow.isEnabled = false
                val imported = syncManager.importIfNewerOnDisk()
                binding.btnImportNow.isEnabled = true
                showStatus(
                    if (imported) getString(R.string.sync_imported)
                    else getString(R.string.sync_up_to_date)
                )
            }
        }
    }

    private fun saveTitle() {
        val title = binding.etAppTitle.text?.toString()?.trim() ?: ""
        if (title.isNotEmpty()) vm.setAppTitle(title)
    }

    private fun updateSyncModeLabel() {
        binding.tvSyncMode.text = if (prefs.syncEnabled)
            getString(R.string.sync_mode_file)
        else
            getString(R.string.sync_mode_local)
    }

    private fun updateFolderDisplay() {
        val active = prefs.syncEnabled
        val uriStr = prefs.syncFolderUri

        // Folder controls only matter when sync is on
        binding.tvSyncFolder.visibility    = if (active) View.VISIBLE else View.GONE
        binding.btnChooseFolder.visibility = if (active) View.VISIBLE else View.GONE

        if (!active) {
            binding.btnClearFolder.visibility = View.GONE
            binding.btnSyncNow.isEnabled      = false
            binding.btnImportNow.isEnabled    = false
            return
        }

        if (uriStr == null) {
            binding.tvSyncFolder.text         = getString(R.string.no_folder_chosen)
            binding.btnClearFolder.visibility  = View.GONE
            binding.btnSyncNow.isEnabled      = false
            binding.btnImportNow.isEnabled    = false
        } else {
            val df = DocumentFile.fromTreeUri(requireContext(), Uri.parse(uriStr))
            binding.tvSyncFolder.text         = df?.name ?: uriStr
            binding.btnClearFolder.visibility  = View.VISIBLE
            binding.btnSyncNow.isEnabled      = true
            binding.btnImportNow.isEnabled    = true
        }
    }

    private fun showStatus(msg: String) { binding.tvSyncStatus.text = msg }

    override fun onDestroyView() {
        super.onDestroyView()
        scope.cancel()
        _binding = null
    }
}
