package id.hyperdemit;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public interface KeyPairAlgorithm {
    String getName();
    KeyPair generateKeyPair() throws NoSuchAlgorithmException;
}
