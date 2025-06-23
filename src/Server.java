import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class Server {
    public static void main(String[] args) throws Exception {
        int port = 1234;
        DiffieHellman serverDH = new DiffieHellman();
        BigInteger B = serverDH.getPublicKey();

        String serverUsername = "b7rb7s7"; 
        String privateKeyPath = "keys/server.pem";

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Servidor escutando na porta " + port);

            try (Socket client = serverSocket.accept()) {
                System.out.println("Cliente conectado.");

                DataInputStream receive = new DataInputStream(client.getInputStream());
                DataOutputStream send = new DataOutputStream(client.getOutputStream());

                BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

                // === Handshake ===
                int frameLen = receive.readInt();
                byte[] frame = new byte[frameLen];
                receive.readFully(frame);
                MessageUtils.HandshakeMessage msgClient = MessageUtils.parseFrame(frame);

                BigInteger A = msgClient.A;
                String clientUsername = msgClient.username;

                PublicKey clientPublicKey = KeyUtils.downloadGitHubECDSAKey(clientUsername, 1);
                byte[] dataToVerify = concatAUsername(A, clientUsername);
                if (!KeyUtils.verifySignature(dataToVerify, msgClient.signature, clientPublicKey)) {
                    System.out.println("Assinatura do cliente inválida! Encerrando.");
                    return;
                }
                PrivateKey privKey = KeyUtils.loadECPrivateKey(privateKeyPath);
                byte[] dataToSign = concatAUsername(B, serverUsername);
                byte[] signature = KeyUtils.signData(dataToSign, privKey);
                byte[] responseFrame = MessageUtils.buildFrame(B, signature, serverUsername);
                send.writeInt(responseFrame.length);
                send.write(responseFrame);
                // key derivation
                BigInteger sharedSecret = serverDH.sharedSecret(A);
                SecretKey aesKey = CryptoUtils.deriveAESKey(sharedSecret.toByteArray());
                SecretKey hmacKey = CryptoUtils.deriveHMACKey(sharedSecret.toByteArray());
                // === Handshake done ===
                System.out.println("Handshake concluído. Chat seguro iniciado. Digite 'sair' para encerrar.");

                Thread receiveThread = new Thread(() -> {
                    try {
                        while (true) {
                            int msgLen = receive.readInt();
                            byte[] packet = new byte[msgLen];
                            receive.readFully(packet);

                            byte[] hmac = Arrays.copyOfRange(packet, 0, 32);
                            byte[] iv = Arrays.copyOfRange(packet, 32, 48);
                            byte[] cipherText = Arrays.copyOfRange(packet, 48, packet.length);

                            byte[] ivAndCipher = concat(iv, cipherText);
                            System.out.println();
                            System.out.println("[DEBUG][INCOMING] Segredo compartilhado (DH): " + sharedSecret.toString(16));
                            System.out.println("[DEBUG][INCOMING] IV: " + bytesToHex(iv));
                            System.out.println("[DEBUG][INCOMING] HMAC: " + bytesToHex(hmac));
                            System.out.println("[DEBUG][INCOMING] Texto cifrado (Base64): ");
                            
                            try {
                                boolean ok = CryptoUtils.verifyHMAC(ivAndCipher, hmac, hmacKey);
                                if (!ok) {
                                    System.out.println("HMAC inválido. Mensagem ignorada.");
                                    continue;
                                }

                                byte[] plaintext = CryptoUtils.decryptAES(cipherText, aesKey, iv);
                                System.out.println("\nCliente: " + new String(plaintext, StandardCharsets.UTF_8));
                                System.out.print("> ");
                            } catch (Exception e) {
                                System.out.println("Erro ao verificar ou descriptografar mensagem: " + e.getMessage());
                            }
                        }
                    } catch (Exception e) {
                        System.out.println("Conexão encerrada pelo cliente.");
                    }
                });

                receiveThread.start();

                // Send messages to the client
                SecureRandom random = new SecureRandom();
                while (true) {
                    System.out.print("> ");
                    String line = consoleReader.readLine();
                    if (line == null || line.equalsIgnoreCase("sair"))
                        break;

                    byte[] iv = new byte[16];
                    random.nextBytes(iv);

                    byte[] cipherText = CryptoUtils.encryptAES(line.getBytes(StandardCharsets.UTF_8), aesKey, iv);
                    byte[] ivAndCipher = concat(iv, cipherText);
                    byte[] hmac = CryptoUtils.calculateHMAC(ivAndCipher, hmacKey);
                    byte[] packet = concat(hmac, ivAndCipher);

                    send.writeInt(packet.length);
                    send.write(packet);
                    System.out.println("[DEBUG][OUTGOING] Segredo compartilhado (DH): " + sharedSecret.toString(16));
                    System.out.println("[DEBUG][OUTGOING] IV: " + bytesToHex(iv));
                    System.out.println("[DEBUG][OUTGOING] HMAC: " + bytesToHex(hmac));
                    System.out.println("[DEBUG][OUTGOING] Texto cifrado (Base64): "
                            + java.util.Base64.getEncoder().encodeToString(cipherText));
                }

                System.out.println("Encerrando conexão.");
                client.close();
                receiveThread.join();
            }
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

    // For debug only
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
