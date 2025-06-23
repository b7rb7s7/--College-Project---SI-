import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DHSignatureUtils {

    // Join A and username in bytes[]
    private static byte[] concatAUsername(BigInteger A, String username) {
        byte[] aBytes = A.toByteArray(); 
        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);

        byte[] combined = new byte[aBytes.length + userBytes.length];
        System.arraycopy(aBytes, 0, combined, 0, aBytes.length);
        System.arraycopy(userBytes, 0, combined, aBytes.length, userBytes.length);

        return combined;
    }

    // Sign A + username using the private key
    public static byte[] signDHValue(BigInteger A, String username, PrivateKey privKey) throws Exception {
        byte[] message = concatAUsername(A, username);
        return KeyUtils.signData(message, privKey);
    }

    // Verify the signature using the public key
    public static boolean verifyDHSignature(BigInteger A, String username, byte[] signature, PublicKey pubKey) throws Exception {
        byte[] message = concatAUsername(A, username);
        return KeyUtils.verifySignature(message, signature, pubKey);
    }
}
