package id.hyperdemit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Optional;

class Decryption {
    private final String keyPairAlgorithm;
    private final String encryptAlgorithmName;

    Decryption(String keyPairAlgorithm, String encryptAlgorithmName) {
        this.keyPairAlgorithm = keyPairAlgorithm;
        this.encryptAlgorithmName = encryptAlgorithmName;
    }

    public byte[] decrypt(byte[] data, List<byte[]> encryptedSecretKeyList, byte[] privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyNoMatchException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Optional<byte[]> secretKey = decryptSecretKey(encryptedSecretKeyList, bytesToPrivateKey(privateKey));
        if (!secretKey.isPresent()) {
            throw new KeyNoMatchException("Cannot unlock the encrypted data with this key.");
        }

        return decryptData(data, secretKey.get());
    }

    private PrivateKey bytesToPrivateKey(byte[] privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance(keyPairAlgorithm);

        return factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    }

    private Optional<byte[]> decryptSecretKey(List<byte[]> encryptedSecretKeyList, PrivateKey privateKey) {
        for (byte[] encryptedSecretKey: encryptedSecretKeyList) {
            Optional<byte[]> decrypt = tryDecryptSecretKey(encryptedSecretKey, privateKey);
            if (decrypt.isPresent()) {
                return decrypt;
            }
        }

        return Optional.empty();
    }

    private Optional<byte[]> tryDecryptSecretKey(byte[] encryptedSecretKey, PrivateKey privateKey) {
        try {
            return Optional.of(decryptSecretKeyByPrivateKey(encryptedSecretKey, privateKey));
        }  catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            return Optional.empty();
        }
    }

    private byte[] decryptSecretKeyByPrivateKey(byte[] encryptedSecretKey, PrivateKey key) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return finalDecrypt(encryptedSecretKey, key, keyPairAlgorithm);
    }

    private byte[] decryptData(byte[] data, byte[] secretKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return finalDecrypt(data, new SecretKeySpec(secretKey, encryptAlgorithmName), encryptAlgorithmName);
    }

    private byte[] finalDecrypt(byte[] input, Key key, String algorithmName) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(input);
    }
}
