package cat.uvic.teknos.m09.uf1;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class CryptoUtils {

    public static void AsymmetricEncryption(String t) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        var text = t.repeat(2).getBytes();

        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        var keyPair = keyPairGenerator.generateKeyPair();

        var cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        var cipherText = cipher.doFinal(text);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        var decryptedText = cipher.doFinal(cipherText);

        var base64Encoder = Base64.getEncoder();

        System.out.println("Plain text: " + new String(text));
        System.out.println("Cipher text: " + base64Encoder.encodeToString(cipherText));
        System.out.println("Decrypted text: " + new String(decryptedText));

    }

    public static String getDigest(String data, byte[] salt) throws NoSuchAlgorithmException {
        var dataBytes = data.getBytes();

        var messageDigest = MessageDigest.getInstance("SHA-256");

        messageDigest.update(salt);
        var digest = messageDigest.digest(dataBytes);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    public static byte[] getSalt(){
        var secureRandom = new SecureRandom();

        var salt = new byte[16];
        secureRandom.nextBytes(salt);

        return salt;
    }

    public static void SymetricEncryption(String t) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        var text = t.repeat(15);

        var secretKey = getPrivateKeyFromPassword("teknos");

        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");


        var secureRandom = new SecureRandom();
        var bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        var iv = new IvParameterSpec(bytes);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        var cipherText = cipher.doFinal(text.getBytes());

        var base64Encoder = Base64.getEncoder();
        var cipherTextBase64 = base64Encoder.encodeToString(cipherText);

        System.out.println("Encrypted text: " + cipherTextBase64);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        var decryptedTextBytes = cipher.doFinal(cipherText);
        var decryptedText = new String(decryptedTextBytes);

        System.out.println("Decrypted text: " + decryptedText);
    }

    private static Key getPrivateKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[100];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), "AES");

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        var salt = getSalt();
        var digest = getDigest("teknos", salt);

        AsymmetricEncryption("This is the example text");
        SymetricEncryption("This is the example text");


    }


}
