package id.hyperdemit;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyPair implements KeyPairAlgorithm {
    public static final int DEFAULT_KEY_SIZE = 1024;
    private final int keySize;

    public RSAKeyPair(int keySize) {
        this.keySize = keySize;
    }

    public RSAKeyPair() {
        this.keySize = DEFAULT_KEY_SIZE;
    }

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(getName());
        generator.initialize(keySize);

        return generator.generateKeyPair();
    }

    @Override
    public String getName() {
        return "RSA";
    }
}
