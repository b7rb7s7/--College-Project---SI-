import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;


//meant for testing signature, concat and key downloader

public class Test {
    public static void main(String[] args) {
        try {
            String username = "b7rb7s7"; 
            String privateKeyPath = "keys/client_fake.pem";        

            BigInteger A = new BigInteger("1234567890123456789012345678901234567890");//not acual dh value
            PrivateKey privKey = KeyUtils.loadECPrivateKey(privateKeyPath);
            
            PublicKey pubKey = KeyUtils.downloadGitHubECDSAKey(username, 1);

            
            byte[] dateToSign = concatAUsername(A, username);

            
            byte[] signature = KeyUtils.signData(dateToSign, privKey);
            boolean valid = KeyUtils.verifySignature(dateToSign, signature, pubKey);

            System.out.println("Assinatura válida? " + valid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] concatAUsername(BigInteger A, String username) {
        byte[] aBytes = A.toByteArray();
        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[aBytes.length + userBytes.length];

        System.arraycopy(aBytes, 0, combined, 0, aBytes.length);
        System.arraycopy(userBytes, 0, combined, aBytes.length, userBytes.length);

        return combined;
    }
}
