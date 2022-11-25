import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Cipher;

import javax.crypto.spec.SecretKeySpec;

public class SHA_HMAC_AES {
    // global variables
    private BigInteger opad;
    private BigInteger ipad;
    private BigInteger hashedKey;
    private String aesKey;

    // constructor
    SHA_HMAC_AES() {
        // generate opad and ipad
        this.opad = new BigInteger(generatePads("5c", 32), 16);
        this.ipad = new BigInteger(generatePads("36", 32), 16);
    }

    public String[] encrypt(String message) {
        String iv = generateIV();
        // divide message into 4 blocks
        String[] blocks = splitMessageIntoBlocks(message);
        try {
            // create key
            aesKey = (String) hashedKey.toString().subSequence(0, 24);
            byte[] keyByteArrray = aesKey.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyByteArrray, "AES");
            // create cipher using aes, ecb and no padding
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            String encryptMsg = "";
            String prevMsgBlock = iv;
            // begin encryption
            for (int i = 0; i < 4; i++) {
                prevMsgBlock = aesCbcEncryptionRound(blocks[i], prevMsgBlock, cipher);
                encryptMsg += prevMsgBlock;
            }
            // finish encryption

            // create hmac of encryption
            BigInteger hmac = generateHMAC(encryptMsg + iv);

            // create request
            String[] request = new String[3];
            request[0] = encryptMsg;
            request[1] = iv;
            request[2] = hmac.toString(0);

            return request;

        } catch (Exception e) {
            System.out.println("Invalid key");
            System.out.println(e);
            System.exit(-1);
        }
        return null;
    }

    public String aesCbcEncryptionRound(String block, String prevBlock, Cipher cipher) {
        try {
            // xor block to be encrypted with iv or previous encrypted bloock
            String xorBlock = xorTwoStrings(block, getFirstSixteenCharacters(prevBlock));
            // encrypt xorBlock with aes
            byte[] encrypted = cipher.doFinal(xorBlock.getBytes());
            String cipherText = Base64.getEncoder().encodeToString(encrypted);
            return cipherText;
        } catch (Exception e) {
            System.out.println("Invalid message");
            System.exit(-1);
        }
        return "";
    }

    public String decrypt(String[] request) throws Exception {
        String encryptedMessage = request[0];
        String iv = request[1];
        String hmacMessage = request[2];

        // check if message has been altered
        BigInteger hmac = generateHMAC(encryptedMessage + iv);
        if (!hmacMessage.matches(hmac.toString())) {
            System.out.println("HMAC invalid, message has been altered");
            System.exit(-1);
        }

        String[] blocks = splitEncryptedMessageIntoBlocks(encryptedMessage, iv);

        String decryptedMessage = "";

        try {
            // create key
            aesKey = (String) hashedKey.toString().subSequence(0, 24);
            byte[] keyByteArrray = aesKey.getBytes();
            SecretKeySpec secretKey = new SecretKeySpec(keyByteArrray, "AES");
            // create cipher using aes, ecb and no padding
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            // begin decryption
            for (int i = 0; i < 4; i++) {
                String[] result = aesCbcDecryptionRound(blocks[i + 1], blocks[i], cipher);
                decryptedMessage += result[1];
            }
            return decryptedMessage;
        } catch (Exception e) {
            System.out.println("Invalid key");
            System.exit(-1);
        }
        return "";
    }

    public String[] aesCbcDecryptionRound(String block, String prevBlock, Cipher cipher) {
        String[] prevBlock_EncryptedBlock = new String[2];
        prevBlock_EncryptedBlock[0] = block;
        try {
            // decrypt using aes
            byte[] aesDecryptedBytes = cipher.doFinal(Base64.getDecoder().decode(block));
            String aesDecrypted = new String(aesDecryptedBytes);
            // decrypt using xor with prevMessageBlock
            String xorDecrypted = xorDecrypt(aesDecrypted, getFirstSixteenCharacters(prevBlock));
            prevBlock_EncryptedBlock[1] = xorDecrypted;
            return prevBlock_EncryptedBlock;
        } catch (Exception e) {
            System.out.println(e);
            System.out.println("Invalid message");
        }

        return prevBlock_EncryptedBlock;
    }

    public String getFirstSixteenCharacters(String encryptedString) {
        return (String) encryptedString.subSequence(0, 16);
    }

    public String xorDecrypt(String xorStr, String key) {
        String keyStr = convertStringToBinary(key);
        char[] keyChar = keyStr.toCharArray();
        char[] xorChar = xorStr.toCharArray();

        // convert char array to int array
        int[] intBinary1 = new int[keyChar.length];
        int[] intBinary2 = new int[xorChar.length];
        for (int i = 0; i < keyChar.length; i++) {
            intBinary1[i] = Integer.parseInt(Character.toString(keyChar[i]));
        }
        for (int i = 0; i < xorChar.length; i++) {
            intBinary2[i] = Integer.parseInt(Character.toString(xorChar[i]));
        }
        // perform xor
        String xorDecrypted = "";
        for (int i = 0; i < intBinary1.length; i++) {
            xorDecrypted += Integer.toString(intBinary1[i] ^ intBinary2[i]);
        }

        // split binary string into array
        String[] binaryStringsArray = new String[16];
        int j = 0;
        for (int i = 0; i < binaryStringsArray.length; i++) {
            binaryStringsArray[i] = (String) xorDecrypted.subSequence(j, j + 8);
            j += 8;
        }

        // convert binaryString array into text
        String plainText = "";
        for (int i = 0; i < binaryStringsArray.length; i++) {
            char wordChar = (char) Integer.parseInt(binaryStringsArray[i], 2);

            plainText += Character.toString(wordChar);

        }
        return plainText;

    }

    public String xorTwoStrings(String str1, String str2) {
        // convert both strings to binary
        String binaryStr1 = convertStringToBinary(str1);
        String binaryStr2 = convertStringToBinary(str2);

        // convert string to char array
        char[] char1 = binaryStr1.toCharArray();
        char[] char2 = binaryStr2.toCharArray();

        // convert char array to int array
        int[] intBinary1 = new int[binaryStr1.length()];
        int[] intBinary2 = new int[binaryStr2.length()];
        for (int i = 0; i < char1.length; i++) {
            intBinary1[i] = Integer.parseInt(Character.toString(char1[i]));
        }
        for (int i = 0; i < char1.length; i++) {
            intBinary2[i] = Integer.parseInt(Character.toString(char2[i]));
        }
        // perform xor
        String xorStr = "";
        for (int i = 0; i < intBinary1.length; i++) {
            xorStr += Integer.toString(intBinary1[i] ^ intBinary2[i]);
        }

        return xorStr;
    }

    public static String convertStringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        char[] chars = input.toCharArray();
        for (char aChar : chars) {
            result.append(
                    String.format("%8s", Integer.toBinaryString(aChar))
                            .replaceAll(" ", "0"));
        }
        return result.toString();

    }

    private String[] splitMessageIntoBlocks(String message) {

        String[] blocks = new String[4];
        blocks[0] = (String) message.subSequence(0, 16);
        blocks[1] = (String) message.subSequence(16, 32);
        blocks[2] = (String) message.subSequence(32, 48);
        blocks[3] = (String) message.subSequence(48, 64);
        return blocks;

    }

    private String[] splitEncryptedMessageIntoBlocks(String encryptedMessage, String iv) {
        String[] blocks = new String[5];
        blocks[0] = iv;
        blocks[1] = (String) encryptedMessage.subSequence(0, 172);
        blocks[2] = (String) encryptedMessage.subSequence(172, 344);
        blocks[3] = (String) encryptedMessage.subSequence(344, 516);
        blocks[4] = (String) encryptedMessage.subSequence(516, 688);

        return blocks;
    }

    public String generateIV() {
        String iv = UUID.randomUUID().toString();
        iv = iv.replace("-", "");
        iv = (String) iv.subSequence(0, 16);
        return iv;
    }

    // HMAC

    public String generatePads(String value, int iterations) {
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < iterations; i++) {
            pad.append(value);
        }
        return pad.toString();
    }

    public BigInteger generateHMAC(String msgInput) {
        BigInteger key = hashedKey;
        BigInteger kOpad = key.xor(opad);
        BigInteger kIpadMHash = generateHash(key.xor(ipad).toString(), msgInput);
        BigInteger hash = generateHash(kOpad.toString(), kIpadMHash.toString());
        return hash;
    }

    public BigInteger generateHMAC(BigInteger keyInput, String msgInput) {
        BigInteger key = generateHash(keyInput.toString(), "");
        this.hashedKey = key;

        BigInteger kOpad = key.xor(opad);
        BigInteger kIpadMHash = generateHash(key.xor(ipad).toString(), msgInput);
        BigInteger hash = generateHash(kOpad.toString(), kIpadMHash.toString());
        return hash;
    }

    public BigInteger generateHash(String str1, String str2) {
        String stringToBeHashed = str1 + str2;
        byte[] hash;
        try {
            hash = getSHA(stringToBeHashed);
            String hexStringHash = toHexString(hash);
            BigInteger bigInt = new BigInteger(hexStringHash, 16);
            return bigInt;
        } catch (Exception e) {
            System.out.println("Error");
            System.exit(-1);
        }
        return null;
    }

    // SHA

    public static byte[] getSHA(String input) throws NoSuchAlgorithmException {
        // hash using sha-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHexString(byte[] hash) {
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));
        return hexString.toString();
    }

    // fast modular exponentiation

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

}
