package co.tob.charan.encrytion

import android.annotation.TargetApi
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import co.tob.charan.utils.hasMarshmallow
import co.tob.charan.utils.toByteArray
import java.security.*
import javax.crypto.Cipher

class RsaKeystoreWrapper {

    companion object{
        const val AES_NOPAD_TRANS = "RSA/ECB/PKCS1Padding"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "Keyalaisras"
    }

    private fun createKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore
    }

    fun createAsymmetricKeyPair(): KeyPair {
        val generator: KeyPairGenerator

        if (hasMarshmallow()) {
            generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            getKeyGenParameterSpec(generator)
        } else {
            generator = KeyPairGenerator.getInstance("RSA")
            generator.initialize(2048)
        }

        return generator.generateKeyPair()
    }

    @TargetApi(23)
    private fun getKeyGenParameterSpec(generator: KeyPairGenerator) {

        val builder = KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            //.setUserAuthenticationRequired(true)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)

        generator.initialize(builder.build())
    }

    fun getAsymmetricKeyPair(): KeyPair? {
        val keyStore: KeyStore = createKeyStore()

        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey?
        val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey

        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    fun removeKeyStoreKey() = createKeyStore().deleteEntry(KEY_ALIAS)

    fun encrypt(data: String, key: Key?): String {
        val cipher: Cipher = Cipher.getInstance(AES_NOPAD_TRANS)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val bytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(bytes, Base64.DEFAULT)
    }

    fun decrypt(data: String, key: Key?): String {
        val cipher: Cipher = Cipher.getInstance(AES_NOPAD_TRANS)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedData = Base64.decode(data, Base64.DEFAULT)
        val decodedData = cipher.doFinal(encryptedData)
        return String(decodedData)
    }

}