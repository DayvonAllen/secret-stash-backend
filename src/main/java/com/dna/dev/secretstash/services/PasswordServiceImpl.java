package com.dna.dev.secretstash.services;

import com.dna.dev.secretstash.exceptions.SecretStashException;
import com.dna.dev.secretstash.model.RequestObjectDto;
import com.dna.dev.secretstash.util.PasswordGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

@Service
public class PasswordServiceImpl implements PasswordService {

    private final PasswordGenerator passwordGenerator;
    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    public PasswordServiceImpl(PasswordGenerator passwordGenerator) {
        this.passwordGenerator = passwordGenerator;
    }

    @Override
    public RequestObjectDto getRandomPassword() {
        try {
            RequestObjectDto requestObjectDto = new RequestObjectDto();
            requestObjectDto.setPassword(passwordGenerator.hashPassword(passwordGenerator.generateRandomPassword()));
            return requestObjectDto;
        } catch (NoSuchAlgorithmException e){
            LOGGER.error("Can't generate password");
            throw new SecretStashException("Problem generating password");
        }
    }

    @Override
    public RequestObjectDto createSecurePassword(RequestObjectDto requestObjectDto) {
        try {
            RequestObjectDto newPassword = new RequestObjectDto();
            newPassword.setPassword(passwordGenerator
                    .hashPassword(passwordGenerator.generateBase64Password(requestObjectDto.getPassword())));
            return newPassword;
        } catch (NoSuchAlgorithmException e){
            LOGGER.error("Can't generate password");
            throw new SecretStashException("Problem generating password");
        }

    }
}
