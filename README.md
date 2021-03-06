# Je2e

### Basic Usage
``` java
//...

Je2e je2e = new Je2e(new RSAKeyPair());

try {
    KeyPairGenerator keyPair = je2e.getKeyPairGenerator();
    byte[] publicKey = keyPair.getPublicKey();
    byte[] privateKey = keyPair.getPrivateKey();

    String secretData = "This is secret data";
    byte[] bytesSecretData = secretData.getBytes(StandardCharsets.UTF_8);
    Encrypted encrypted = je2e.encrypt(bytesSecretData, List.of(publicKey));

    byte[] decryptData = je2e.decrypt(encrypted.getData(), encrypted.getSecretKeyList(), privateKey);
    String receiveData = new String(decryptData, StandardCharsets.UTF_8);

    // receiveData is equal secretData

} catch (KeyNoMatchException e) {
    System.out.println(e.getMessage());
} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
    e.printStackTrace();
}

//...
```

### Using Gson
``` java
public class ExampleWithGson {
    public static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
        @Override
        public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            return Base64.getDecoder().decode(json.getAsString());
        }

        @Override
        public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base64.getEncoder().encodeToString(src));
        }
    }

    public void withGsonTest() {
        Gson customGson = new GsonBuilder()
                .registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
                .create();

        Je2e je2e = new Je2e(new RSAKeyPair());

        try {
            KeyPairGenerator keyPair = je2e.getKeyPairGenerator();
            byte[] publicKey = keyPair.getPublicKey();
            byte[] privateKey = keyPair.getPrivateKey();

            String secretData = "This is secret data";
            byte[] bytesSecretData = secretData.getBytes(StandardCharsets.UTF_8);
            Encrypted encrypted = je2e.encrypt(bytesSecretData, List.of(publicKey));
            String jsonSecretData = customGson.toJson(encrypted);

            System.out.println(jsonSecretData);

            Encrypted fromJson = customGson.fromJson(jsonSecretData, Encrypted.class);

            byte[] decryptData = je2e.decrypt(fromJson.getData(), fromJson.getSecretKeyList(), privateKey);
            String receiveData = new String(decryptData, StandardCharsets.UTF_8);

            // receiveData is equal secretData
            System.out.println("secret data is: " + receiveData) ;

        } catch (KeyNoMatchException e) {
            System.out.println(e.getMessage());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
```