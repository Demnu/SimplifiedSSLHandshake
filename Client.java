import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;

public class Client {
    private final static String RECIEVED = "Recieved message from server:";
    private static String clientID = "c3282352";
    private static SHA_HMAC_AES shaHmacAes;
    private static BigInteger[] serverPublicKey;
    private static EphemeralDiffieHellman ephemeralDiffieHellman;
    private static String serverID;
    private static String sessionID;

    public static void main(String[] args) {
        shaHmacAes = new SHA_HMAC_AES();
        String[] messageFromServer;
        String[] messageToServer;
        try {
            // connect to server
            Socket socket = new Socket("localhost", 7777);
            System.out.println("Connected! \n");

            InputStream inputStream = socket.getInputStream();
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            // send hello to server.
            messageToServer = new String[1];
            messageToServer[0] = "HELLO from client!";
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent hello message to server \n");

            // recieve public key from server
            System.out.println(RECIEVED);
            messageFromServer = (String[]) objectInputStream.readObject();
            System.out.println("e:");
            System.out.println(messageFromServer[0]);
            System.out.println("n:");
            System.out.println(messageFromServer[1]);
            System.out.println();

            serverPublicKey = new BigInteger[3];
            serverPublicKey[0] = new BigInteger(messageFromServer[0]);
            serverPublicKey[1] = new BigInteger(messageFromServer[1]);

            // send client id to server
            messageToServer = new String[1];
            messageToServer[0] = clientID;
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent client id to server \n");

            // recieve server id, session id and digital signature from client
            messageFromServer = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            System.out.println("Server id: " + messageFromServer[0]);
            System.out.println("Session id: " + messageFromServer[1]);
            System.out.println("Digital signature: " + messageFromServer[2]);
            isDigitalSignatureVerified(messageFromServer[0], messageFromServer[1],
                    new BigInteger(messageFromServer[2]));
            serverID = messageFromServer[0];
            sessionID = messageFromServer[1];

            // send message to client begin ephemeral DH exchange
            messageToServer = new String[1];
            messageToServer[0] = "initiate ephemeral DH exhange";
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent message to server to initiate ephermeral DH key exchange ");

            // recieve diffie hellman public key from server
            messageFromServer = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            isDigitalSignatureVerified(serverID, sessionID, new BigInteger(messageFromServer[4]));
            System.out.println("Decrypting message with server's public key");
            BigInteger p = decryptUsingServerPublicKey(new BigInteger(messageFromServer[0]));
            BigInteger g = decryptUsingServerPublicKey(new BigInteger(messageFromServer[1]));
            BigInteger serverDHPublicKey = decryptUsingServerPublicKey(new BigInteger(messageFromServer[2]));
            BigInteger nonce = decryptUsingServerPublicKey(new BigInteger(messageFromServer[3]));
            System.out.println("digital signature: " + messageFromServer[4]);
            System.out.println("Decrypted message:");
            System.out.println("p: " + p);
            System.out.println("g: " + g);
            System.out.println("serverDHPublicKey: " + serverDHPublicKey);
            System.out.println("nonce: " + nonce);
            System.out.println();

            // generate dh keys
            // generate ephemeralDiffieHellman private key
            ephemeralDiffieHellman = new EphemeralDiffieHellman(p, g);

            // generate ephemeralDiffieHellman public key using nonce recieved from server
            ephemeralDiffieHellman.generateClientPublicKey(nonce);

            // send diffie-hellman public key to server
            messageToServer = new String[1];
            messageToServer[0] = encryptUsingServerPublicKey(ephemeralDiffieHellman.getPublicKey()).toString(0);
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent public ephemeral DH key to server \n");

            // create dh shared key
            ephemeralDiffieHellman.setSharedKey(serverDHPublicKey);

            // recieve server's HMAC
            messageFromServer = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            isDigitalSignatureVerified(serverID, sessionID, new BigInteger(messageFromServer[1]));
            System.out.println("digital signature: " + messageFromServer[1]);
            System.out.println("Decrypting message with server's public key");
            BigInteger serverDHSharedKeyHMAC = decryptUsingServerPublicKey(new BigInteger(messageFromServer[0]));
            System.out.println("Decrypted message: ");
            System.out.println("Server DH shared key HMAC: " + serverDHPublicKey);
            System.out.println();

            // check if HMAC from server is the same as clients HMAC
            BigInteger clientDHSharedKeyHmac = shaHmacAes.generateHMAC(ephemeralDiffieHellman.getSharedKey(),
                    ephemeralDiffieHellman.getSharedKey().toString());

            if (!clientDHSharedKeyHmac.equals(serverDHSharedKeyHMAC)) {
                System.out.println("Server has different shared key");
                System.out.println("Closing socket and terminating program.");
                socket.close();
                throw new Exception("");
            }

            // send HMAC of DH shared key to server
            messageToServer = new String[1];
            messageToServer[0] = encryptUsingServerPublicKey(clientDHSharedKeyHmac).toString(0);
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent client DH shared key to server \n");

            // recieve dh key exchange success message from server
            messageFromServer = (String[]) objectInputStream.readObject();
            System.out.println(RECIEVED);
            isDigitalSignatureVerified(serverID, sessionID, new BigInteger(messageFromServer[1]));
            System.out.println("digital signature: " + messageFromServer[1]);
            System.out.println("Decrypted message:");
            System.out.println(decryptUsingServerPublicKey(new BigInteger(messageFromServer[0])));
            System.out.println();

            System.out.println("Ephemeral DH key exchange successful");
            System.out.println("Begin data exchange \n");

            // send first message to server
            String message = "You need to grasp the depths of your spiritual connections :) <3";
            System.out.println("Sending first message to server");
            System.out.println("Plaintext: " + message);
            messageToServer = encryptMessage_HMAC_AES_CBC(message);
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent first message to server \n");

            // recieve message from server
            messageFromServer = (String[]) objectInputStream.readObject();
            decryptMessage_HMAC_AES_CBC(messageFromServer);
            System.out.println();

            // send second message to server
            message = "Don\'t just believe in me, believe in you. You need both of us ;)";
            System.out.println("Sending second message to server");
            System.out.println("Plaintext: " + message);
            messageToServer = encryptMessage_HMAC_AES_CBC(message);
            objectOutputStream.writeObject(messageToServer);
            System.out.println("Sent second message to server \n");

            System.out.println("Closing connection");
            socket.close();
        } catch (Exception e) {
            System.out.println("Connection error, exiting program");
            e.printStackTrace();
        }
    }

    public static String[] encryptMessage_HMAC_AES_CBC(String message) {
        return shaHmacAes.encrypt(message);
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

    public static boolean isDigitalSignatureVerified(String serverID, String sessionID,
            BigInteger digitalSignatureFromServer) {
        System.out.println("Verifying digital signature");
        BigInteger hash = shaHmacAes.generateHash(serverID, sessionID);
        BigInteger decrypedDigitalSignature = decryptUsingServerPublicKey(digitalSignatureFromServer);
        if (decrypedDigitalSignature.equals(hash)) {
            System.out.println("Digital signature verified");
            return true;
        } else {
            System.out.println("Invalid digital signature");
            System.exit(-1);
        }
        return false;

    }

    public static BigInteger encryptUsingServerPublicKey(BigInteger value) {
        return SHA_HMAC_AES.powMod(value, serverPublicKey[0], serverPublicKey[1]);

    }

    public static BigInteger decryptUsingServerPublicKey(BigInteger value) {
        return SHA_HMAC_AES.powMod(value, serverPublicKey[0], serverPublicKey[1]);
    }

}
