package id.hyperdemit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

class Encryption {
    private final String keyPairAlgorithm;
    private final String encryptAlgorithmName;

    Encryption(String keyPairAlgorithm, String encryptAlgorithmName) {
        this.keyPairAlgorithm = keyPairAlgorithm;
        this.encryptAlgorithmName = encryptAlgorithmName;
    }

    public Encrypted encrypt(byte[] data, List<byte[]> publicKeys) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final byte[] secretKey = generateSecretKey();

        return new Encrypted(encryptData(data, secretKey), encryptSecretKey(secretKey, byteToPublicKeys(publicKeys)));
    }

    private byte[] generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16];
        random.nextBytes(key);
        SecretKeySpec spec = new SecretKeySpec(key, encryptAlgorithmName);

        return spec.getEncoded();
    }

    private List<PublicKey> byteToPublicKeys(List<byte[]> keys) throws NoSuchAlgorithmException, InvalidKeySpecException {
        List<PublicKey> publicKeys = new ArrayList<>();

        for (byte[] key: keys) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
            KeyFactory factory = KeyFactory.getInstance(keyPairAlgorithm);
            publicKeys.add(factory.generatePublic(spec));
        }

        return publicKeys;
    }

    private List<byte[]> encryptSecretKey(byte[] secretKey, List<PublicKey> publicKeys) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        List<byte[]> encryptedSecretKeys = new ArrayList<>();

        for (PublicKey publicKey: publicKeys) {
            encryptedSecretKeys.add(finalEncrypt(secretKey, publicKey, keyPairAlgorithm));
        }

        return encryptedSecretKeys;
    }

    private byte[] encryptData(byte[] data, byte[] secretKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        SecretKeySpec spec = new SecretKeySpec(secretKey, encryptAlgorithmName);

        return finalEncrypt(data, spec, encryptAlgorithmName);
    }

    private byte[] finalEncrypt(byte[] input, Key key, String algorithmName) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(input);
    }
}
