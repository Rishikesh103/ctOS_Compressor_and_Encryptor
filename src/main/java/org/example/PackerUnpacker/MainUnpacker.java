package org.example.PackerUnpacker;

import com.github.luben.zstd.ZstdInputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class MainUnpacker {
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int SALT_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final byte TYPE_DIRECTORY = 0;
    private static final byte TYPE_FILE = 1;

    private void log(String message) {
        System.out.println("[" + LocalTime.now().format(timeFormatter) + "] " + message);
    }

    public void unpack(String sourceFilePath, String destDirPath, char[] password) throws GeneralSecurityException, IOException {
        File destDir = new File(destDirPath);
        if (!destDir.exists()) destDir.mkdirs();

        log("// DedSec Unpacking Protocol Initialized_");
        log("-> Analyzing payload: " + sourceFilePath);

        try (RandomAccessFile raf = new RandomAccessFile(sourceFilePath, "r")) {
            log("// Reading security layer...");
            byte[] salt = new byte[SALT_LENGTH];
            raf.readFully(salt);
            SecretKey secretKey = generateSecretKey(password, salt);
            log("-> Decryption key loaded into memory.");

            log("// Beginning data extraction (Streaming + Decompression)...");

            int counter = 0;
            while (raf.getFilePointer() < raf.length()) {
                System.out.print(".");
                if (++counter % 80 == 0) System.out.println();

                int type = raf.readByte();

                int pathLength = raf.readInt();
                byte[] pathBytes = new byte[pathLength];
                raf.readFully(pathBytes);
                File outputFile = new File(destDir, new String(pathBytes, StandardCharsets.UTF_8));

                if (type == TYPE_DIRECTORY) {
                    outputFile.mkdirs();
                } else if (type == TYPE_FILE) {
                    byte[] iv = new byte[GCM_IV_LENGTH];
                    raf.readFully(iv);
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

                    outputFile.getParentFile().mkdirs();

                    long encryptedDataLength = raf.readLong();

                    InputStream fis = Channels.newInputStream(raf.getChannel());
                    InputStream limitedStream = new LimitedInputStream(fis, encryptedDataLength);

                    try (FileOutputStream fos = new FileOutputStream(outputFile);
                         CipherInputStream cis = new CipherInputStream(limitedStream, cipher);
                         ZstdInputStream zis = new ZstdInputStream(cis)) {

                        zis.transferTo(fos);
                    }
                }
            }
            System.out.println();
            log("// Finalizing extraction...");
            log("-> All data restored. File handles closed.");
        }
    }

    public List<String> listContents(String sourceFilePath, char[] password) throws IOException, GeneralSecurityException {
        List<String> contents = new ArrayList<>();
        try (RandomAccessFile raf = new RandomAccessFile(sourceFilePath, "r")) {
            byte[] salt = new byte[SALT_LENGTH];
            raf.readFully(salt);
            generateSecretKey(password, salt);

            while (raf.getFilePointer() < raf.length()) {
                int type = raf.readByte();

                int pathLength = raf.readInt();
                byte[] pathBytes = new byte[pathLength];
                raf.readFully(pathBytes);
                String relativePath = new String(pathBytes, StandardCharsets.UTF_8);

                if (type == TYPE_DIRECTORY) {
                    contents.add("[DIR]  " + relativePath);
                } else if (type == TYPE_FILE) {
                    contents.add("[FILE] " + relativePath);
                    raf.skipBytes(GCM_IV_LENGTH);
                    long encryptedDataLength = raf.readLong();
                    raf.seek(raf.getFilePointer() + encryptedDataLength);
                }
            }
        }
        return contents;
    }

    private SecretKey generateSecretKey(char[] password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}

// Helper class to limit how much data an InputStream can read
class LimitedInputStream extends InputStream {
    private final InputStream original;
    private long limit;

    public LimitedInputStream(InputStream original, long limit) {
        this.original = original;
        this.limit = limit;
    }

    @Override
    public int read() throws IOException {
        if (limit <= 0) return -1;
        limit--;
        return original.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (limit <= 0) return -1;
        int bytesToRead = (int) Math.min(len, limit);
        int bytesRead = original.read(b, off, bytesToRead);
        if (bytesRead > 0) limit -= bytesRead;
        return bytesRead;
    }
}