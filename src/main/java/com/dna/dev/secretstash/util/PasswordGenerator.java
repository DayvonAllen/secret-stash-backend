package com.dna.dev.secretstash.util;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    public String generateBase64PasswordWithCustomSalt(String password, String salt) {
        if(salt == null){
            salt = "";
        }
        String saltedPassword = password + salt;
        byte[] newPassword = saltedPassword.getBytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(newPassword);
    }

    public String generateBase64PasswordWithCustomSalt20(String password, String salt) {
        if(salt == null){
            salt = "";
        }
        String saltedPassword = salt + password;
        byte[] newPassword = saltedPassword.getBytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(newPassword);
    }

    public String hashPassword(String newPassword) throws NoSuchAlgorithmException {
        byte[] bytes = newPassword.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        byte[] digest = messageDigest.digest();

        String result = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        Pattern regex = Pattern.compile("[^A-Za-z0-9]");
        Matcher matcher = regex.matcher(result);
        if(!matcher.find()){
            result += result + "!";
        }
        return result;
    }

    public String hashPassword20(String newPassword) throws NoSuchAlgorithmException {
        byte[] bytes = newPassword.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        byte[] digest = messageDigest.digest();
        StringBuilder password = new StringBuilder();
        String result =  Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        for(int i = 0; i < 20; i++){
            password.append(result.charAt(i));
        }

        Pattern regex = Pattern.compile("[^A-Za-z0-9]");
        Matcher matcher = regex.matcher(password);

        if(!matcher.find()){
            password.append("!");
        }

        return password.toString();
    }

    public String generateRandomPassword() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPassword = new byte[32];
        secureRandom.nextBytes(randomPassword);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomPassword);
    }
}
