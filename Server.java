import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class Server {
    private final static String RECIEVED = "Recieved message from client:";

    private static String serverID = "dfgwre7yurt7nhgdhf";
    private static String sessionID = "gr75u9tbcecvrv1";
    private static SHA_HMAC_AES shaHmacAes;
    private static BigInteger[] publicKey;
    private static BigInteger[] privateKey;
    private static BigInteger n;
    private static BigInteger e = BigInteger.valueOf(65537);
    private static EphemeralDiffieHellman ephemeralDiffieHellman;
    private static BigInteger g;
    private static BigInteger p;

    public static void main(String[] args) {
        publicKey = new BigInteger[2];
        privateKey = new BigInteger[3];
        shaHmacAes = new SHA_HMAC_AES();
        keyGeneration();

        String[] messageFromClient;
        String[] messageToClient;
        try {
            ServerSocket serverSocket = new ServerSocket(7777);
            System.out.println("Awaiting connection from client");
            Socket socket = serverSocket.accept();
            System.out.println("Client has connected \n");

            // setup connection to client
            InputStream inputStream = socket.getInputStream();
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            // recieve hello from client
            messageFromClient = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            System.out.println(messageFromClient[0]);
            System.out.println();

            // send public key to client
            messageToClient = new String[2];
            messageToClient[0] = publicKey[0].toString();
            messageToClient[1] = publicKey[1].toString();
            objectOutputStream.writeObject(messageToClient);
            System.out.println("Sent public key to client \n");

            // recieve clientID from server
            messageFromClient = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            System.out.println("ClientID: " + messageFromClient[0]);
            System.out.println();

            // send server id, session id and digital signature to client
            messageToClient = new String[3];
            messageToClient[0] = serverID;
            messageToClient[1] = sessionID;
            messageToClient[2] = sendDigitalSignatureToClient().toString();
            objectOutputStream.writeObject(messageToClient);
            System.out.println("Sent server id, session id and digital signature to client\n");

            // recieve message from client to intiate ephemeral DH exchange
            messageFromClient = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            System.out.println("Message: " + messageFromClient[0]);
            generatePrivateAndPublicDiffieHellmanKeys();

            // send diffie hellman public key to client
            messageToClient = getDiffieHellmanPublicKey();
            objectOutputStream.writeObject(messageToClient);
            System.out.println("Sent DH public key to client\n");

            // recieve client's public DH key
            messageFromClient = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            System.out.println("Decrypting message with private key");
            BigInteger clientDHPublicKey = decryptClientMessageUsingPrivateKey(new BigInteger(messageFromClient[0]));
            System.out.println("Decrypted message:");
            System.out.println("Client public DH key: " + clientDHPublicKey);
            System.out.println();

            // create dh shared key
            ephemeralDiffieHellman.setSharedKey(clientDHPublicKey);

            // send HMAC of DH shared key to client
            messageToClient = getSharedKeyHMAC();
            objectOutputStream.writeObject(messageToClient);
            System.out.println("Sent DH shared key to client \n");

            // recieve clients HMAC of dh shared key
            messageFromClient = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            System.out.println("Decrypting message with private key");
            BigInteger clientDHSharedKeyHmac = decryptClientMessageUsingPrivateKey(
                    new BigInteger(messageFromClient[0]));
            System.out.println("Decrypted message:");
            System.out.println("Client DH shared key HMAC: " + clientDHSharedKeyHmac);
            System.out.println();

            // check if HMAC from client is the same as server's HMAC
            sharesSameSharedKey(clientDHSharedKeyHmac);
            System.out.println("Ephemeral DH key exchange successful \n");

            // send DH key exhange successful message to client
            messageFromClient = new String[1];
            messageToClient = getSharedKeyHMAC();
            objectOutputStream.writeObject(messageToClient);
            System.out.println("Sent success message to client \n");
            System.out.println("Begin data exchange \n");

            // recieve first message from client
            messageFromClient = (String[]) objectInputStream.readObject();
            decryptMessage_HMAC_AES_CBC(messageFromClient);
            System.out.println();

            // send message to client
            String message = "Stop sending me that spiritual garbage, I am a computer beep bop";
            System.out.println("Sending message to server");
            System.out.println("Plaintext: " + message);
            messageToClient = shaHmacAes.encrypt(message);
            objectOutputStream.writeObject(messageToClient);
            System.out.println("Sent message to server \n");

            // recieve second message from client
            messageFromClient = (String[]) objectInputStream.readObject();
            decryptMessage_HMAC_AES_CBC(messageFromClient);
            System.out.println();

            System.out.println("Closing connection");
            serverSocket.close();
            socket.close();
        } catch (Exception e) {
            System.out.println("Connection error, exiting program");
            e.printStackTrace();
        }

    }

    public static void decryptMessage_HMAC_AES_CBC(String[] message) {
        System.out.println(RECIEVED);
        System.out.println("Encrypted message: " + message[0]);
        System.out.println("IV: " + message[1]);
        System.out.println("HMAC: " + message[2]);
        System.out.println("Decrypting message");
        String plainText;
        try {
            plainText = shaHmacAes.decrypt(message);
            System.out.println("Plaintext: " + plainText);

        } catch (Exception e) {
            System.out.println("Error decrypting message");
            e.printStackTrace();
        }
    }

    public static BigInteger decryptClientMessageUsingPrivateKey(BigInteger message) {
        return SHA_HMAC_AES.powMod(message, privateKey[2], n);

    }

    public static void keyGeneration() {
        // generate two primes
        Random tempP = new Random();
        Random tempQ = new Random();
        BigInteger p = BigInteger.probablePrime(1024, tempP);
        BigInteger q = BigInteger.probablePrime(1024, tempQ);

        n = p.multiply(q);
        BigInteger pMinusOne = p.subtract(new BigInteger("1"));
        BigInteger QMinusOne = q.subtract(new BigInteger("1"));
        BigInteger orderN = pMinusOne.multiply(QMinusOne);

        BigInteger d = e.modInverse(orderN);

        publicKey[0] = e;
        publicKey[1] = n;

        privateKey[0] = p;
        privateKey[1] = q;
        privateKey[2] = d;
    }

    public static BigInteger sendDigitalSignatureToClient() {
        // hash serverID and sessionID
        BigInteger hash = shaHmacAes.generateHash(serverID, sessionID);
        // encrypt hash with private key
        BigInteger digitalSignature = encryptUsingPrivateKey(hash);
        return digitalSignature;

    }

    public static void generatePrivateAndPublicDiffieHellmanKeys() {
        p = new BigInteger(
                "178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
        g = new BigInteger(
                "174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");

        ephemeralDiffieHellman = new EphemeralDiffieHellman(p, g);
        ephemeralDiffieHellman.generateNonces();
        ephemeralDiffieHellman.generateServerPublicKey();
    }

    public static String[] getDiffieHellmanPublicKey() {
        String[] message = new String[5];
        message[0] = encryptUsingPrivateKey(ephemeralDiffieHellman.getP()).toString(0);
        message[1] = encryptUsingPrivateKey(ephemeralDiffieHellman.getG()).toString(0);
        message[2] = encryptUsingPrivateKey(ephemeralDiffieHellman.getPublicKey()).toString(0);
        message[3] = encryptUsingPrivateKey(ephemeralDiffieHellman.getNonce()).toString(0);
        message[4] = sendDigitalSignatureToClient().toString(0);
        return message;
    }

    public static void recieveClientDiffieHellmanPublicKey(BigInteger clientDiffieHellmanPublicKey) {
        System.out.println("Server:");
        System.out.println("Recieved client's Diffie-Hellman public key");
        ephemeralDiffieHellman.setSharedKey(clientDiffieHellmanPublicKey);
        System.out.println("Generating Shared Key");
        System.out.println("Generated Shared Key");
        System.out.println();
    }

    public static BigInteger encryptUsingPrivateKey(BigInteger value) {
        BigInteger encryptedValue = SHA_HMAC_AES.powMod(value, privateKey[2], n);
        return encryptedValue;
    }

    public static boolean sharesSameSharedKey(BigInteger sharedKeyFromClient) {
        BigInteger sharedKeyServerHmac = shaHmacAes.generateHMAC(ephemeralDiffieHellman.getSharedKey(),
                ephemeralDiffieHellman.getSharedKey().toString());
        if (sharedKeyFromClient.equals(sharedKeyServerHmac)) {
            return true;

        } else {
            System.out.println("Shared key is not the same");
            System.exit(-1);
        }
        return false;
    }

    public static String[] getSharedKeyHMAC() {
        BigInteger sharedKeyServer = shaHmacAes.generateHMAC(ephemeralDiffieHellman.getSharedKey(),
                ephemeralDiffieHellman.getSharedKey().toString());
        String[] message = new String[2];
        message[0] = encryptUsingPrivateKey(sharedKeyServer).toString(0);
        message[1] = sendDigitalSignatureToClient().toString(0);

        return message;
    }
}
