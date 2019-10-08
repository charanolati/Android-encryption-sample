package co.tob.encryption

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import co.tob.charan.constants.EncType
import co.tob.charan.constants.EncryptConstants.ENC_VALUE
import co.tob.charan.constants.EncryptConstants.IV_VALUE
import co.tob.charan.constants.EncryptConstants.SALT_VALUE
import co.tob.charan.encrytion.AesKeystoreWrapper
import co.tob.charan.encrytion.AesSaltEncryption
import co.tob.charan.encrytion.RsaKeystoreWrapper
import co.tob.charan.utils.*
import kotlinx.android.synthetic.main.activity_encrypt.*
import java.security.KeyPair

@Suppress("UNCHECKED_CAST")
class EncryptActivity : AppCompatActivity() {

    private var isencrypt = true
    private lateinit var dataHashMap : HashMap<String, ByteArray>

    private var encType = EncType.AESENCRYPT

    private lateinit var rsaKeystoreWrapper : RsaKeystoreWrapper
    private lateinit var rsaKeyPair : KeyPair
    private var encrypteData : String = ""

    private lateinit var aesKeystoreWrapper: AesKeystoreWrapper

    private lateinit var aesSaltEncryption: AesSaltEncryption

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encrypt)

        //To Check Lock Screen Enabled or not
        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if(!isDeviceSecure(keyguardManager)) showDeviceSecurityAlert(this)

        if(Build.VERSION.SDK_INT >= 23) {
            aesToggleBtn.isChecked = true

            aesKeystoreWrapper = AesKeystoreWrapper()
            aesSaltEncryption = AesSaltEncryption()

        }else{
            aesSaltToggleBtn.isEnabled = false
            aesToggleBtn.isEnabled = false
            aesSaltToggleBtn.visibility = View.GONE
            aesToggleBtn.visibility = View.GONE

            rsaToggleBtn.isChecked = true
            encType = EncType.RSAENCRYPT
        }

        rsaKeystoreWrapper = RsaKeystoreWrapper()

        encryptToggleGrp.addOnButtonCheckedListener { _, checkedId, isChecked ->
            run {
                if(isChecked) {

                    encType =
                        when (checkedId) {
                            aesToggleBtn.id -> EncType.AESENCRYPT
                            aesSaltToggleBtn.id -> EncType.AESALTENCRYPT
                            else -> EncType.RSAENCRYPT
                        }

                    isencrypt = true
                    dataHashMap = HashMap()
                    encrypteData = ""
                    encryptButton.text = "Encrypt"
                    inputEt.text = null
                    dataTV.text = null
                }
            }
        }
    }

    @SuppressLint("SetTextI18n")
    fun onEncyptClicked(v : View){

        v.hideKeyboard()

        if(isencrypt){

            val data: String = inputEt.text.toString()
            if(data.isEmpty()){
                Toast.makeText(this,"Enter Data",Toast.LENGTH_SHORT).show()
                return
            }

            val response = encryptData(data)

            encryptButton.text = "Decrypt"
            isencrypt = false
            if(response is HashMap<*, *>) {
                dataHashMap = response as HashMap<String, ByteArray>

                val ss: StringBuilder = StringBuilder()
                    ss.append("$encType EN-crypted Data \n\nIV - ${dataHashMap[IV_VALUE]!!.fromBytetoString()}" +
                        "\nENC - ${dataHashMap[ENC_VALUE]!!.fromBytetoString()}")
                if(encType == EncType.AESALTENCRYPT){
                    ss.append("\nSLAT - ${dataHashMap[SALT_VALUE]!!.fromBytetoString()}")
                }

                dataTV.text = ss.toString()
            } else if(response is String) {
                encrypteData = response
                dataTV.text = "$encType EN-crypted Data \n\nENC - $response"
            }

        }else{

            val data = if(encType == EncType.AESENCRYPT || encType == EncType.AESALTENCRYPT ) { decryptData(dataHashMap)!! }else{ decryptData(encrypteData)}

            encryptButton.text = "Encrypt"
            isencrypt = true

            inputEt.text = null
            dataTV.text = "$encType DE-crypted Data \n\nDEC - $data"

        }
    }

    @SuppressLint("NewApi")
    private fun encryptData(data: String) : Any? {

        return when (encType) {
            EncType.AESENCRYPT -> {
                aesKeystoreWrapper.encryptData(data.toByteArray())
            }
            EncType.AESALTENCRYPT -> aesSaltEncryption.encrypt(data.toByteArray())
            else -> {

                if(hasMarshmallow()) {
                    rsaKeystoreWrapper.createAsymmetricKeyPair()
                    rsaKeyPair = rsaKeystoreWrapper.getAsymmetricKeyPair()!!
                }else{
                    rsaKeyPair = rsaKeystoreWrapper.createAsymmetricKeyPair()
                }
                rsaKeystoreWrapper.encrypt(data,rsaKeyPair.public)
            }
        }
    }

    @SuppressLint("NewApi")
    private fun decryptData(data: Any) : String? {
        return when (encType) {
            EncType.AESENCRYPT -> aesKeystoreWrapper.decryptData(data as HashMap<String, ByteArray>)
            EncType.AESALTENCRYPT -> aesSaltEncryption.decrypt(data as HashMap<String, ByteArray>)
            else -> rsaKeystoreWrapper.decrypt(data as String, rsaKeyPair.private)
        }
    }

    @Suppress("SENSELESS_COMPARISON")
    override fun onDestroy() {
        if(::rsaKeyPair.isInitialized)rsaKeystoreWrapper.removeKeyStoreKey()
        super.onDestroy()
    }

}