import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class MessageUtils {

    public static byte[] buildFrame(BigInteger A, byte[] signature, String username) throws IOException {
        byte[] aBytes = A.toByteArray();
        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out);

        dataOut.writeInt(aBytes.length);
        dataOut.write(aBytes);

        dataOut.writeInt(signature.length);
        dataOut.write(signature);

        dataOut.writeInt(userBytes.length);
        dataOut.write(userBytes);

        return out.toByteArray();
    }

    public static HandshakeMessage parseFrame(byte[] frame) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(frame));

        int lenA = in.readInt();
        byte[] aBytes = new byte[lenA];
        in.readFully(aBytes);
        BigInteger A = new BigInteger(aBytes);

        int lenSig = in.readInt();
        byte[] signature = new byte[lenSig];
        in.readFully(signature);

        int lenUser = in.readInt();
        byte[] userBytes = new byte[lenUser];
        in.readFully(userBytes);
        String username = new String(userBytes, StandardCharsets.UTF_8);

        return new HandshakeMessage(A, signature, username);
    }

    public static class HandshakeMessage {
        public final BigInteger A;
        public final byte[] signature;
        public final String username;

        public HandshakeMessage(BigInteger A, byte[] signature, String username) {
            this.A = A;
            this.signature = signature;
            this.username = username;
        }
    }
}
