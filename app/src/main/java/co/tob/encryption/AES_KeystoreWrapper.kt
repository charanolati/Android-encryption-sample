package co.tob.charan.encrytion

import android.annotation.SuppressLint
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import co.tob.charan.constants.EncryptConstants.ENC_VALUE
import co.tob.charan.constants.EncryptConstants.IV_VALUE
import co.tob.charan.utils.fromBytetoString
import co.tob.charan.utils.toByteArray
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

//AES Encryption will be available after API 23+ (ANDROID M)
class AesKeystoreWrapper {

    companion object{
        const val AES_NOPAD_TRANS = "AES/GCM/NoPadding" //Format - ”Algorithm/Mode/Padding”
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "Keyalaisasf"
    }

    private fun createKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore
    }

    //@Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    @RequiresApi(23)
    fun createSymmetricKey() : SecretKey {
        try{
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)

            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                //.setUserAuthenticationRequired(true) //  requires lock screen, invalidated if lock screen is disabled
                //.setUserAuthenticationValidityDurationSeconds(120) // only available x seconds from password authentication. -1 requires finger print - every time
    //            .setKeySize(256) // Set key size
                //To Set Certificate Values instead of maual initialization of certificate
    //            .setCertificateNotBefore(startDate) // By default, this date is Jan 1 1970.
    //            .setCertificateNotAfter(endDate) // By default, this date is Jan 1 2048.
    //            .setCertificateSerialNumber(number) // By default, the serial number is 1.
    //            .setCertificateSubject(x500Principal) // By default, the subject is CN=fake.

                .setRandomizedEncryptionRequired(true) // 4 different ciphertext for same plaintext on each call
                .build()
            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to create a symmetric key", e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to create a symmetric key", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException("Failed to create a symmetric key", e)
        }
    }

    fun decryptData(hashMap: HashMap<String, ByteArray>): String {

        val encryptedBytes = Base64.decode(hashMap[ENC_VALUE],Base64.NO_WRAP)
        val ivBytes = Base64.decode(hashMap[IV_VALUE],Base64.NO_WRAP)

        val cipher = Cipher.getInstance(AES_NOPAD_TRANS)
        cipher.init(Cipher.DECRYPT_MODE, getSymmetricKey(), GCMParameterSpec(128, ivBytes))

        return cipher.doFinal(encryptedBytes).fromBytetoString()
    }

    fun encryptData(data: ByteArray): HashMap<String, ByteArray> {

        val cipher = Cipher.getInstance(AES_NOPAD_TRANS)
        cipher.init(Cipher.ENCRYPT_MODE, getSymmetricKey())

        val eiv = (Base64.encodeToString(cipher.iv,Base64.NO_WRAP)).toByteArray()
        val edata = (Base64.encodeToString(cipher.doFinal(data),Base64.NO_WRAP)).toByteArray()

        return hashMapOf(Pair(IV_VALUE,eiv),Pair(ENC_VALUE,edata))
    }

    fun decryptNoBase(ivBytes : ByteArray,encryptedBytes : ByteArray): String {

        val cipher = Cipher.getInstance(AES_NOPAD_TRANS)
        cipher.init(Cipher.DECRYPT_MODE, getSymmetricKey(), GCMParameterSpec(128, ivBytes))

        return cipher.doFinal(encryptedBytes).fromBytetoString()
    }

    @SuppressLint("NewApi")
    fun getSymmetricKey(): SecretKey {
        /*val keysore = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
        return keysore.secretKey*/

        val keyStore = createKeyStore()

        if(!isKeyExists(keyStore)){
            createSymmetricKey()
        }

        return keyStore.getKey(KEY_ALIAS,null) as SecretKey
    }

    fun removeKeyStoreKey() {
        val keyStore = createKeyStore()

        if(isKeyExists(keyStore)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    fun isKeyExists(keyStore : KeyStore): Boolean {
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            return (KEY_ALIAS == aliases.nextElement())
        }
        return false
    }

    fun getCipher(): Cipher {
        val key = getSymmetricKey()
        val cipher = Cipher.getInstance(AES_NOPAD_TRANS)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        return cipher
    }
}