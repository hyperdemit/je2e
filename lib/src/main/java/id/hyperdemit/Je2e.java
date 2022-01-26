package id.hyperdemit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class Je2e {
    private final KeyPairAlgorithm algorithm;
    private final String ENCRYPT_ALGORITHM_NAME = "AES";

    public Je2e(KeyPairAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException {
        return new KeyPairGenerator(algorithm.generateKeyPair());
    }

    public Encrypted encrypt(byte[] data, List<byte[]> publicKeys) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        return new Encryption(algorithm.getName(), ENCRYPT_ALGORITHM_NAME).encrypt(data, publicKeys);
    }

    public byte[] decrypt(byte[] data, List<byte[]> encryptedSecretKeyList, byte[] privateKey) throws KeyNoMatchException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        return new Decryption(algorithm.getName(), ENCRYPT_ALGORITHM_NAME).decrypt(data, encryptedSecretKeyList, privateKey);
    }
}
