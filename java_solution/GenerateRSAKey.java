import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

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
            String publicKeyFile = outputPath + "/public_key.der";
            String privateKeyFile = outputPath + "/private_key.der";

            byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
            byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();

            // Create directory if does not exist
            try {
                Files.createDirectories(outputPath);
            } catch (IOException e) {
                System.err.println("Failed to create directory: " + e.getMessage());
            }
            
            // Write to a file
            try (FileOutputStream publicOS = new FileOutputStream(publicKeyFile)) {
                publicOS.write(encodedPublicKey);
            }

            try (FileOutputStream privateOS = new FileOutputStream(privateKeyFile)) {
                privateOS.write(encodedPrivateKey);
            }

            System.out.println("Successfully generated RSA Public key: " + publicKeyFile);
            System.out.println("Successfully generated RSA Private key: " + privateKeyFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
