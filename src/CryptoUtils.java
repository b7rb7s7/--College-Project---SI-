import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.SecureRandom;

public class CryptoUtils {
    private static final byte[] SALT = "FIXED_SALT".getBytes(); // Hardcoded SALT value, as suggested.
    private static final int ITERATIONS = 150000;

    public static SecretKey deriveAESKey(byte[] sharedSecret) throws Exception {
        return deriveKey(sharedSecret, 16, "AES");
    }

    public static byte[] generateRandomIV() {
        byte[] iv = new byte[16]; // 16 bytes = 128 bits
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
    // Although the SALT and DH secret are the same for both AES and HMAC keys,
    // using a different lenght generates different keys, in this case 128 bits for 
    // the AES key and 256 bits for the HMAC key
    public static SecretKey deriveHMACKey(byte[] sharedSecret) throws Exception {
        return deriveKey(sharedSecret, 32, "HmacSHA256"); // 32 bytes = 256 bits
    }

    private static SecretKey deriveKey(byte[] password, int keyLengthBytes, String algorithm) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
                toCharArray(password), SALT, ITERATIONS, keyLengthBytes * 8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, algorithm);
    }

    private static char[] toCharArray(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }
        return chars;
    }

    public static byte[] encryptAES(byte[] plaintext, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decryptAES(byte[] ciphertext, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    public static byte[] calculateHMAC(byte[] data, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    public static boolean verifyHMAC(byte[] data, byte[] receivedHmac, SecretKey hmacKey) throws Exception {
        byte[] expected = calculateHMAC(data, hmacKey);
        return MessageDigest.isEqual(expected, receivedHmac);
    }

}
