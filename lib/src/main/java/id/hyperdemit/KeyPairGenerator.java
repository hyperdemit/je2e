package id.hyperdemit;

import java.security.KeyPair;

public class KeyPairGenerator {
    private final KeyPair keyPair;

    public KeyPairGenerator(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public byte[] getPublicKey() {
        return keyPair.getPublic().getEncoded();
    }

    public byte[] getPrivateKey() {
        return keyPair.getPrivate().getEncoded();
    }
}
