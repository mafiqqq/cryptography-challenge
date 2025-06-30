import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GenerateRSAKey {
    
    /**
     * 
     * @param keySize RSA Key Size
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateRSAKey(int keySize) throws NoSuchAlgorithmException {
        System.out.println("Generating RSA Key pair..");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) {
        try {
            // Generate the RSA key
            KeyPair keyPair = generateRSAKey(2048);

            
            // Save the keyPair to file
            Path outputPath = Paths.get("java_solution/output_files");
            String publicKeyFile = outputPath + "/public_key.pem";
            String privateKeyFile = outputPath + "/private_key.pem";

            byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
            byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();

            // Base64 encode the bytes
            String publicKeyBase64 = Base64.getEncoder().encodeToString(encodedPublicKey);
            String privateKeyBase64 = Base64.getEncoder().encodeToString(encodedPrivateKey);

            String privatePem = "-----BEGIN RSA PRIVATE KEY-----\n" + privateKeyBase64 + "\n-----END RSA PRIVATE KEY-----";
            String publicPem = "-----BEGIN RSA PUBLIC KEY-----\n" + publicKeyBase64 + "\n-----END RSA PUBLIC KEY-----";
            
            // Create directory if does not exist
            try {
                Files.createDirectories(outputPath);
            } catch (IOException e) {
                System.err.println("Failed to create directory: " + e.getMessage());
            }
            
            // Write to a file
            try (FileWriter writer = new FileWriter(publicKeyFile)) {
                writer.write(publicPem);
            }

            try (FileWriter writer = new FileWriter(privateKeyFile)) {
                writer.write(privatePem);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
