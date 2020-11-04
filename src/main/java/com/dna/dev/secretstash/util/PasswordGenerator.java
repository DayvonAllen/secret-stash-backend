package com.dna.dev.secretstash.util;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class PasswordGenerator {

    private final Environment environment;

    public PasswordGenerator(Environment environment) {
        this.environment = environment;
    }

    public String generateBase64Password(String password) {
        String saltedPassword = password + environment.getProperty("salt");
        byte[] newPassword = saltedPassword.getBytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(newPassword);
    }

    public String hashPassword(String newPassword) throws NoSuchAlgorithmException {
        byte[] bytes = newPassword.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        byte[] digest = messageDigest.digest();

        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public String generateRandomPassword() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPassword = new byte[32];
        secureRandom.nextBytes(randomPassword);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomPassword);
    }
}
