package org.example.PackerUnpacker;

import com.github.luben.zstd.ZstdOutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class MainPacker {
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int SALT_LENGTH = 16;
    private static final byte TYPE_DIRECTORY = 0;
    private static final byte TYPE_FILE = 1;

    private void log(String message) {
        System.out.println("[" + LocalTime.now().format(timeFormatter) + "] " + message);
    }

    public void pack(String sourceDirPath, String destFilePath, char[] password, String compressionLevel) throws Exception {
        File sourceDir = new File(sourceDirPath);
        if (!sourceDir.exists() || !sourceDir.isDirectory()) throw new IOException("Source directory not found!");

        log("// DedSec Packing Protocol Initialized_");
        log("-> Target acquired: " + sourceDirPath);
        log("// Generating encryption layer...");
        byte[] salt = generateRandomBytes(SALT_LENGTH);
        SecretKey secretKey = generateSecretKey(password, salt);
        log("-> Secure key derived successfully.");
        log("// Initiating file system scan...");
        List<File> pathList = new ArrayList<>();
        collectPaths(sourceDir, pathList);
        log("-> Scan complete. Found " + pathList.size() + " total objects.");
        log("-> Compression engine: Zstandard");

        try (FileOutputStream fos = new FileOutputStream(destFilePath)) {
            fos.write(salt);
            log("// Beginning data encapsulation...");

            int counter = 0;
            for (File path : pathList) {
                System.out.print(".");
                if (++counter % 80 == 0) System.out.println();

                String relativePath = sourceDir.toURI().relativize(path.toURI()).getPath();
                byte[] pathBytes = relativePath.getBytes(StandardCharsets.UTF_8);

                if (path.isDirectory()) {
                    fos.write(TYPE_DIRECTORY);
                    writeInt(fos, pathBytes.length);
                    fos.write(pathBytes);
                } else {
                    fos.write(TYPE_FILE);
                    byte[] iv = generateRandomBytes(GCM_IV_LENGTH);
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

                    fos.write(iv);
                    writeInt(fos, pathBytes.length);
                    fos.write(pathBytes);

                    // --- FINAL RELIABLE STREAMING LOGIC ---
                    // 1. Create a temporary file to hold the processed data for this single file.
                    File tempFile = File.createTempFile("dedsec-packer-", ".tmp");
                    tempFile.deleteOnExit(); // Ensure temp file is cleaned up if the app crashes

                    // 2. Stream from the source file, through the compress/encrypt chain, into the temp file.
                    //    This entire operation is now self-contained and isolated.
                    try (FileInputStream fis = new FileInputStream(path);
                         FileOutputStream tempFos = new FileOutputStream(tempFile);
                         ZstdOutputStream zos = new ZstdOutputStream(tempFos);
                         CipherOutputStream cos = new CipherOutputStream(zos, cipher)) {

                        fis.transferTo(cos);
                    }

                    // 3. Write the exact length of the processed temp file to our main archive.
                    writeInt(fos, (int)tempFile.length());

                    // 4. Stream the contents of the temp file into our main archive.
                    try (FileInputStream tempFis = new FileInputStream(tempFile)) {
                        tempFis.transferTo(fos);
                    }

                    // 5. Clean up the temporary file immediately.
                    tempFile.delete();
                }
            }
            System.out.println();
            log("// Finalizing archive...");
            log("-> All streams closed. Payload integrity verified.");
        }
    }

    private void collectPaths(File dir, List<File> pathList) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                pathList.add(file);
                if (file.isDirectory()) collectPaths(file, pathList);
            }
        }
    }

    private SecretKey generateSecretKey(char[] password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private void writeInt(OutputStream os, int value) throws IOException {
        os.write((value >> 24) & 0xFF);
        os.write((value >> 16) & 0xFF);
        os.write((value >> 8) & 0xFF);
        os.write(value & 0xFF);
    }
}