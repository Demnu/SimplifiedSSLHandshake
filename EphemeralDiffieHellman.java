import java.math.BigInteger;
import java.util.LinkedList;
import java.util.Random;

public class EphemeralDiffieHellman {
    // global variables
    private BigInteger g;
    private BigInteger p;
    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger sharedKey;
    private LinkedList<BigInteger> nonces;

    // constructor
    EphemeralDiffieHellman(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        generatePrivateKey();
    }

    public void generatePublicKey() {
        this.publicKey = powMod(g, privateKey, p);
    }

    public void generateServerPublicKey() {
        this.publicKey = powMod(g, privateKey.multiply(nonces.getFirst()), p);
        System.out.println("g: " + g + "\n");
        System.out.println("e: " + privateKey.multiply(nonces.getFirst()) + "\n");
        System.out.println("p: " + p + "\n");
        System.out.println("answer: " + publicKey);
    }

    public void generateClientPublicKey(BigInteger nonce) {
        this.publicKey = powMod(g, privateKey.multiply(nonce), p);

    }

    public void generateNonces() {
        nonces = new LinkedList<>();
        for (int i = 0; i < 5; i++) {
            Random rand = new Random();
            BigInteger result = new BigInteger(p.bitLength(), rand);
            while (result.compareTo(p) >= 0) {
                result = new BigInteger(p.bitLength(), rand);
            }
            nonces.add(result);
        }

    }

    private void generatePrivateKey() {
        Random rand = new Random();
        this.privateKey = new BigInteger(256, rand);

    }

    public static BigInteger powMod(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger tempBase = base;
        // followed pseudocode but does not work
        BigInteger result = new BigInteger("0");
        base = base.mod(modulus);
        for (int i = 0; i < exponent.bitLength(); i++) {
            if (exponent.testBit(i)) {
                result = result.multiply(base).mod(modulus);
            }
            base = base.multiply(base).mod(modulus);
        }

        return tempBase.modPow(exponent, modulus);
    }

    // getters
    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getSharedKey() {
        return sharedKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public LinkedList<BigInteger> getNonces() {
        return nonces;
    }

    public BigInteger getNonce() {
        if (!nonces.isEmpty()) {
            return nonces.poll();
        }
        generateNonces();
        return getNonce();
    }

    // setters
    public void setSharedKey(BigInteger inputKey) {
        this.sharedKey = powMod(inputKey, privateKey, p);
    }

}
