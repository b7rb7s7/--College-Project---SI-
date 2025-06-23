import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman{
    //Hardcoded DH prime and generator numbers, as suggested.
    //Ideally, I should've used something like:
    //KeyFactory kf = KeyFactory.getInstance("DH");
    //from the java.security lib on both server and client
    //sides instead of creating an external DH class.
    //But I wanted to try implementing DH myself
    
    DiffieHellman(){
        this.privateKey = generatePrivateKey();
        this.publicKey = calculatePubicKey();
    }

    private final BigInteger p = new BigInteger("1298074214633706835075030044377087");//Prime
    private final BigInteger g = new BigInteger("3");                                 //Generator
    private BigInteger privateKey;
    private BigInteger publicKey;

    private BigInteger generatePrivateKey(){
        return new BigInteger(1024, new SecureRandom()); //This should return a random 1024 bit number
    }
    private BigInteger calculatePubicKey(){
        return g.modPow(this.privateKey, p); //The modPow() method was used instead of the regular ^ and % operators 
                                             //because those can lead to inaccuracies or overflow when working with big numbers
    }
    public BigInteger sharedSecret(BigInteger publicKey){
        return publicKey.modPow(this.privateKey, p);      
    }
    public BigInteger getPublicKey() {
        return this.publicKey;
    }

    /*testing
    public static void main(String[] args) {
        DiffieHellman alice = new DiffieHellman();
        DiffieHellman bob = new DiffieHellman();

        BigInteger alicePublicKey = alice.getPublicKey();
        BigInteger bobPublicKey = bob.getPublicKey();

        BigInteger aliceSharedSecret = alice.sharedSecret(bobPublicKey);
        BigInteger bobSharedSecret = bob.sharedSecret(alicePublicKey);

        System.out.println(aliceSharedSecret);
        System.out.println(bobSharedSecret);
    }
    */
}