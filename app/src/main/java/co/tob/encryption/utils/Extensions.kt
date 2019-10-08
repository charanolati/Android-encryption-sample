package co.tob.charan.utils

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

fun String.toByteArray() = this.toByteArray(Charsets.UTF_8)

fun ByteArray.fromBytetoString() = String(this,Charsets.UTF_8)

fun Context.openLockScreenSettings() {
    val intent = Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD)
    startActivity(intent)
}

fun View.hideKeyboard() {
    val service: InputMethodManager? = context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
    service?.hideSoftInputFromWindow(windowToken, 0)
}