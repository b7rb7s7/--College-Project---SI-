import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;

public class Client {
    public static void main(String[] args) throws Exception {
        String serverAddress = "localhost";
        int port = 1234;

        String clientUsername = "b7rb7s7"; // client GitHub username
        String serverUsername = "b7rb7s7"; // server GitHub username
        String privateKeyPath = "keys/client.pem";

        DiffieHellman clientDH = new DiffieHellman();
        BigInteger A = clientDH.getPublicKey();

        try (Socket socket = new Socket(serverAddress, port)) {
            DataInputStream receive = new DataInputStream(socket.getInputStream());
            DataOutputStream send = new DataOutputStream(socket.getOutputStream());

            // Sign A + client username
            PrivateKey privKey = KeyUtils.loadECPrivateKey(privateKeyPath);
            byte[] dataToSign = concatAUsername(A, clientUsername);
            byte[] signature = KeyUtils.signData(dataToSign, privKey);

            // Handshake
            byte[] frame = MessageUtils.buildFrame(A, signature, clientUsername);
            send.writeInt(frame.length);
            send.write(frame);

            // Gets response from the server
            int len = receive.readInt();
            byte[] serverFrame = new byte[len];
            receive.readFully(serverFrame);
            MessageUtils.HandshakeMessage serverMessage = MessageUtils.parseFrame(serverFrame);

            // Signature verification
            PublicKey pubKeyServidor = KeyUtils.downloadGitHubECDSAKey(serverUsername, 0);
            byte[] serverDataToVerify = concatAUsername(serverMessage.A, serverUsername);
            boolean validSignature = KeyUtils.verifySignature(serverDataToVerify, serverMessage.signature,
                    pubKeyServidor);
            if (!validSignature) {
                System.out.println("Assinatura do servidor inválida! Encerrando.");
                return;
            }

            // AES and HMAC keys derivation based on the DH secret
            BigInteger sharedSecret = clientDH.sharedSecret(serverMessage.A);
            SecretKey aesKey = CryptoUtils.deriveAESKey(sharedSecret.toByteArray());
            SecretKey hmacKey = CryptoUtils.deriveHMACKey(sharedSecret.toByteArray());

            System.out.println("Chat seguro iniciado. Digite 'sair' para encerrar.");
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            Thread receiveThread = new Thread(() -> {
                try {
                    while (true) {
                        int msgLen = receive.readInt();
                        byte[] packet = new byte[msgLen];
                        receive.readFully(packet);

                        byte[] hmac = new byte[32];
                        byte[] iv = new byte[16];
                        byte[] cipherText = new byte[msgLen - 48];

                        System.arraycopy(packet, 0, hmac, 0, 32);
                        System.arraycopy(packet, 32, iv, 0, 16);
                        System.arraycopy(packet, 48, cipherText, 0, cipherText.length);

                        byte[] ivCipher = concat(iv, cipherText);
                        System.out.println("[DEBUG] [INCOMING] Segredo compartilhado (DH): " + sharedSecret.toString(16));
                        System.out.println("[DEBUG] [INCOMING] IV: " + bytesToHex(iv));
                        System.out.println("[DEBUG] [INCOMING] HMAC: " + bytesToHex(hmac));
                        System.out.println(
                        "[DEBUG] [INCOMING] Texto cifrado (Base64): " + java.util.Base64.getEncoder().encodeToString(cipherText));
                        try {
                            if (!CryptoUtils.verifyHMAC(ivCipher, hmac, hmacKey)) {
                                System.out.println("HMAC inválido! Mensagem ignorada.");
                                continue;
                            }

                            byte[] plaintext = CryptoUtils.decryptAES(cipherText, aesKey, iv);
                            System.out.println("\nServidor: " + new String(plaintext, StandardCharsets.UTF_8));
                            System.out.print("> ");
                        } catch (Exception e) {
                            System.out.println("Erro ao verificar ou descriptografar mensagem: " + e.getMessage());
                        }
                    }
                } catch (IOException e) {
                    System.out.println("Conexão encerrada pelo servidor.");
                }
            });
            receiveThread.start();

            SecureRandom random = new SecureRandom();

            while (true) {
                System.out.print("> ");
                String msg = console.readLine();
                if (msg == null || msg.equalsIgnoreCase("sair"))
                    break;

                byte[] plaintext = msg.getBytes(StandardCharsets.UTF_8);
                byte[] iv = new byte[16];
                random.nextBytes(iv);
                byte[] ciphertext = CryptoUtils.encryptAES(plaintext, aesKey, iv);
                byte[] ivCipher = concat(iv, ciphertext);
                byte[] hmac = CryptoUtils.calculateHMAC(ivCipher, hmacKey);
                byte[] fullPacket = concat(hmac, ivCipher);
                System.out.println("[DEBUG] [OUTGOING] Segredo compartilhado (DH): " + sharedSecret.toString(16));
                System.out.println("[DEBUG] [OUTGOING] IV: " + bytesToHex(iv));
                System.out.println("[DEBUG] [OUTGOING] HMAC: " + bytesToHex(hmac));
                System.out.println(
                        "[DEBUG] [OUTGOING] Texto cifrado (Base64): " + java.util.Base64.getEncoder().encodeToString(ciphertext));

                send.writeInt(fullPacket.length);
                send.write(fullPacket);

            }

            socket.close();
            receiveThread.join();
        }
    }

    private static byte[] concatAUsername(BigInteger A, String username) {
        byte[] aBytes = A.toByteArray();
        byte[] uBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[aBytes.length + uBytes.length];
        System.arraycopy(aBytes, 0, combined, 0, aBytes.length);
        System.arraycopy(uBytes, 0, combined, aBytes.length, uBytes.length);
        return combined;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
