package co.tob.charan.utils

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import androidx.appcompat.app.AlertDialog
import co.tob.encryption.BuildConfig
import kotlin.system.exitProcess

fun hasMarshmallow() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M


//To check Device has set Screen lock or not
fun isDeviceSecure(keyguardManager : KeyguardManager): Boolean = if (hasMarshmallow()) keyguardManager.isDeviceSecure else keyguardManager.isKeyguardSecure

//To SHOW the Dialog to to Open settings to set a SCREEN LOCK
fun showDeviceSecurityAlert(context: Context): AlertDialog {
    return AlertDialog.Builder(context)
        .setMessage("To Use the App\nSet a Password to Unlock the Screen")
        .setPositiveButton("Settings") { _, _ -> context.openLockScreenSettings() }
        .setNegativeButton("Exit") { _, _ -> run {
            exitProcess(0)
        }
        }
        .setCancelable(BuildConfig.DEBUG)
        .show()
}