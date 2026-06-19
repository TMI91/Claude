package com.example.lists.ui

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.example.lists.data.ListGroup
import com.example.lists.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        supportFragmentManager.addOnBackStackChangedListener {
            supportActionBar?.setDisplayHomeAsUpEnabled(
                supportFragmentManager.backStackEntryCount > 0
            )
        }
        binding.toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }

        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(binding.container.id, HomeFragment())
                .commit()
        }
    }

    fun openSettings() {
        supportFragmentManager.beginTransaction()
            .replace(binding.container.id, SettingsFragment())
            .addToBackStack(null)
            .commit()
    }

    fun openList(group: ListGroup) {
        supportFragmentManager.beginTransaction()
            .replace(binding.container.id, ListDetailFragment.newInstance(group.id, group.name))
            .addToBackStack(null)
            .commit()
    }
}
