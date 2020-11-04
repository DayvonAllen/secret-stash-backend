package com.dna.dev.secretstash.controllers;

import com.dna.dev.secretstash.model.RequestObjectDto;
import com.dna.dev.secretstash.services.PasswordService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/password/")
@CrossOrigin 
public class PasswordController {

    private final PasswordService passwordService;

    public PasswordController(PasswordService passwordService) {
        this.passwordService = passwordService;
    }

    @GetMapping(value = "random", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public RequestObjectDto generateRandomPassword(){
        return passwordService.getRandomPassword();
    }

    @PostMapping(value = "create", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public RequestObjectDto createSecurePassword(@RequestBody RequestObjectDto requestObjectDto){
        return passwordService.createSecurePassword(requestObjectDto);
    }
}
