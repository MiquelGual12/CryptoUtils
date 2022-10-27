package cat.uvic.teknos.m09.uf1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class CryptoUtils {

    public static void AsymmetricEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        var text = "Example text".repeat(2).getBytes();

        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        var keyPair = keyPairGenerator.generateKeyPair();

        var cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        var cipherText = cipher.doFinal(text);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        var decryptedText = cipher.doFinal(cipherText);

        var base64Encoder = Base64.getEncoder();

    }
    
}
