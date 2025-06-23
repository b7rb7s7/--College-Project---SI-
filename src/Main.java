import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {
    public static void main(String[] args) {
        try {
            String username = "b7rb7s7"; // substitua pelo seu usuário GitHub
            String caminhoChavePrivada = "keys/client_fake.pem"; // chave privada local

            // Simula valor DH (A)
            BigInteger A = new BigInteger("1234567890123456789012345678901234567890");

            // Carrega chave privada EC
            PrivateKey privKey = KeyUtils.loadECPrivateKey(caminhoChavePrivada);

            // Baixa chave pública ECDSA do GitHub usando o username
            PublicKey pubKey = KeyUtils.downloadGitHubECDSAKey(username, 1);

            // Concatena A + username em bytes para assinar
            byte[] dataParaAssinar = concatAUsername(A, username);

            // Assina
            byte[] assinatura = KeyUtils.signData(dataParaAssinar, privKey);

            // Verifica assinatura
            System.out.println(assinatura);
            boolean valido = KeyUtils.verifySignature(dataParaAssinar, assinatura, pubKey);

            System.out.println("Assinatura válida? " + valido);

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
