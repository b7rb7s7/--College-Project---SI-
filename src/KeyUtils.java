import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class KeyUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Read private EC key 
    public static PrivateKey loadECPrivateKey(String filePath) throws Exception {
        try (PEMParser parser = new PEMParser(new FileReader(filePath))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (obj instanceof PEMKeyPair) {
                KeyPair keyPair = converter.getKeyPair((PEMKeyPair) obj);
                return keyPair.getPrivate();
            } else {
                throw new IllegalArgumentException("Formato de chave privada inválido.");
            }
        }
    }

    // Gets OpenSSH key from github and converts to PubliKey format
    public static PublicKey downloadGitHubECDSAKey(String githubUser, int index) throws Exception {
        String url = "https://github.com/" + githubUser + ".keys";

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new URL(url).openStream()))) {
            String line;
            int count = 0;

            while ((line = reader.readLine()) != null) {
                if (line.startsWith("ecdsa-sha2-nistp256")) {
                    if (count == index) {
                        String[] parts = line.split(" ");
                        if (parts.length < 2) continue;
                        return parseOpenSSHECDSAPublicKey(parts[1]);
                    }
                    count++;
                }
            }
        }
        throw new Exception("Chave ECDSA não encontrada no índice " + index + " para o usuário " + githubUser);
    }

    private static PublicKey parseOpenSSHECDSAPublicKey(String base64) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64);
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));

        String keyType = readString(in);           
        String curveName = readString(in);         
        byte[] pubKeyBytes = readBytes(in);        

        if (!"ecdsa-sha2-nistp256".equals(keyType) || !"nistp256".equals(curveName)) {
            throw new IllegalArgumentException("Formato ou curva não suportados: " + keyType + " / " + curveName);
        }

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

        ECPoint point = decodeECPoint(pubKeyBytes, ecSpec.getCurve());

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(pubSpec);
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = in.readInt();
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes);
    }

    private static byte[] readBytes(DataInputStream in) throws IOException {
        int length = in.readInt();
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return bytes;
    }

    private static ECPoint decodeECPoint(byte[] encoded, EllipticCurve curve) {
        if (encoded[0] != 0x04) {
            throw new IllegalArgumentException("Apenas pontos EC não comprimidos (uncompressed) são suportados");
        }
        int fieldSize = (curve.getField().getFieldSize() + 7) / 8;
        byte[] x = new byte[fieldSize];
        byte[] y = new byte[fieldSize];
        System.arraycopy(encoded, 1, x, 0, fieldSize);
        System.arraycopy(encoded, 1 + fieldSize, y, 0, fieldSize);
        return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
    }

    // Method to sign the data using the private key
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // Verify signature using the publickey
    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
