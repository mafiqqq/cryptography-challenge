import java.io.FileInputStream;
import java.io.IOError;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class FileEncryptDecrypt {
    
    // Constants
    private static int AES_KEY_SIZE = 256;
    private static int GCM_NONCE_LENGTH = 12;
    private static int GCM_TAG_LENGTH = 16;
    
    public static void encryptFile(Path inputFilePath, Path outPath, PublicKey publicKey) throws Exception {
        System.out.println("Encrypting file: " + inputFilePath.getFileName());

        // Generate random AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        SecretKey aesKey = keyGen.generateKey();

        // Generate random nonce for AES-GCM operation mode
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        // Initialize AES-GCM Cipher
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Read and encrypt file content
        byte[] fileContent = Files.readAllBytes(inputFilePath);
        byte[] encryptedContent = aesCipher.doFinal(fileContent);
        
        // Encrypt the AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        
        // Output structure
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + encryptedAesKey.length + nonce.length + encryptedContent.length);
        byteBuffer.putInt(encryptedAesKey.length);
        byteBuffer.put(encryptedAesKey);
        byteBuffer.put(nonce);
        byteBuffer.put(encryptedContent);

        Files.write(outPath, byteBuffer.array());
    }

    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes;

        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        keyBytes = pemToBytes(pemContent, "-----BEGIN RSA PUBLIC KEY-----","-----END RSA PUBLIC KEY-----");
        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }


    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        byte[] keyBytes = pemToBytes(pemContent, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(spec);
    }


    public static byte[] pemToBytes(String pemContent, String begin, String end) throws IOException {
        int beginIndex = pemContent.indexOf(begin);
        int endIndex = pemContent.indexOf(end);

        if (beginIndex == -1 || endIndex == -1) {
            throw new IOException("Invalid PEM file format");
        }

        String base64Content = pemContent.substring(beginIndex + begin.length(), endIndex)
        .replaceAll("\\s", "");

        return Base64.getDecoder().decode(base64Content);
    }

    public static void main(String[] args) throws Exception {
        // Declare default filePath
        String filePath = "java_solution/AMD image file.JPG";

        // Declare default outputPath
        String outPath = "java_solution/encrypted_output";

        // Load the public key
        PublicKey publicKey = loadPublicKey(filePath);

        // Load the private key
        PrivateKey privateKey = loadPrivateKey(filePath);

        encryptFile(Paths.get(filePath), Paths.get(outPath), publicKey);
        
    }
}
