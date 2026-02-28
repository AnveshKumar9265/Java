package com.example.wso2.mediators;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesCryptoUtil {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static String encrypt(String plainText, String secretKey) throws Exception {
        byte[] keyBytes = secretKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = java.security.SecureRandom.getInstanceStrong().generateSeed(IV_LENGTH);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, parameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());

        byte[] combined = new byte[IV_LENGTH + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, IV_LENGTH);
        System.arraycopy(encrypted, 0, combined, IV_LENGTH, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encryptedBase64, String secretKey) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedBase64);
        
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, IV_LENGTH);

        byte[] cipherText = new byte[combined.length - IV_LENGTH];
        System.arraycopy(combined, IV_LENGTH, cipherText, 0, cipherText.length);

        SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, parameterSpec);

        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText);
    }
}