package com.dna.dev.secretstash.services;

import com.dna.dev.secretstash.model.RequestObjectDto;

public interface PasswordService {

    RequestObjectDto getRandomPassword();
    RequestObjectDto createSecurePassword(RequestObjectDto requestObjectDto);

}
