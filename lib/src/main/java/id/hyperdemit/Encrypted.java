package id.hyperdemit;

import java.util.List;

public class Encrypted {
    private final byte[] dt;
    private final List<byte[]> sk;

    public Encrypted(byte[] data, List<byte[]> secretKeyList) {
        this.dt = data;
        this.sk = secretKeyList;
    }

    public byte[] getData() {
        return dt;
    }

    public List<byte[]> getSecretKeyList() {
        return sk;
    }
}
