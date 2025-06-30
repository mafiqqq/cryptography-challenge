import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GenerateHashSHA {
    
    public static String computeHash(String filePath) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192]; // 
        int bytesRead;
        
        try (InputStream is = new FileInputStream(filePath)) {
            System.out.println("Computing SHA-256 hash of: " + filePath);
            while ((bytesRead = is.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] hashBytes = digest.digest();
        return bytesToHex(hashBytes);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for(byte b: bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        String filePath = "java_solution/AMD image file.JPG";
        // Compute SHA256 Hash
        String hexString = computeHash(filePath);
        System.out.println("Converted into HEX format : " + hexString);
    }
}
