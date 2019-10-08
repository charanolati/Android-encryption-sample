package co.tob.charan.encrytion

import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import co.tob.charan.constants.EncryptConstants.ENC_VALUE
import co.tob.charan.constants.EncryptConstants.IV_VALUE
import co.tob.charan.constants.EncryptConstants.SALT_VALUE
import co.tob.charan.utils.fromBytetoString
import java.security.Key
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

@RequiresApi(23)
class AesSaltEncryption {

  companion object{
    const val ALGORTIHM_TYPE = "PBKDF2WithHmacSHA1"
    const val CPR_TRANSFORMATION = "AES/CBC/PKCS7Padding"//API 23+ //https://miro.medium.com/max/2068/1*MNcknQeCrJMhTWx9JlpnKg.png
    const val ENCRYPT_PASSWORD  = "charan12345"
  }

  fun encrypt(data: ByteArray): HashMap<String, ByteArray> {

    val salt = ByteArray(256)
    SecureRandom().nextBytes(salt)

    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)

    val cipher = Cipher.getInstance(CPR_TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(salt), IvParameterSpec(iv))

    return hashMapOf(Pair(SALT_VALUE,salt),Pair(IV_VALUE,iv),Pair(ENC_VALUE,cipher.doFinal(data)))

  }

  fun decrypt(map: HashMap<String, ByteArray>): String {

    val salt = map[SALT_VALUE]
    val iv = map[IV_VALUE]
    val encrypted = map[ENC_VALUE]

    val cipher = Cipher.getInstance(CPR_TRANSFORMATION)
    cipher.init(Cipher.DECRYPT_MODE, getSecretKey(salt!!), IvParameterSpec(iv))

    return cipher.doFinal(encrypted).fromBytetoString()
  }


  private fun getSecretKey(salt : ByteArray) : Key {
    val pbKeySpec = PBEKeySpec(ENCRYPT_PASSWORD.toCharArray(), salt, 1324, 256)
    val keyBytes = SecretKeyFactory.getInstance(ALGORTIHM_TYPE).generateSecret(pbKeySpec).encoded
    return SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES)
  }

}