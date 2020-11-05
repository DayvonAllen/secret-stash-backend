package com.dna.dev.secretstash.controllers;

import com.dna.dev.secretstash.filter.WebFilter;
import com.dna.dev.secretstash.model.RequestObjectDto;
import com.dna.dev.secretstash.services.PasswordService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJacksonValue;
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
    public MappingJacksonValue generateRandomPassword(){
        WebFilter webFilter = new WebFilter();
        return webFilter.webFilter("BeanFilter", passwordService.getRandomPassword(), "password");
    }

    @PostMapping(value = "create", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public MappingJacksonValue createSecurePassword(@RequestBody RequestObjectDto requestObjectDto){
        WebFilter webFilter = new WebFilter();
        return webFilter.webFilter("BeanFilter", passwordService.createSecurePassword(requestObjectDto), "password");
    }

    @PostMapping(value = "custom", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public MappingJacksonValue createSecurePasswordWithSalt(@RequestBody RequestObjectDto requestObjectDto){
        WebFilter webFilter = new WebFilter();
        return webFilter.webFilter("BeanFilter", passwordService.createSecurePasswordWithSalt(requestObjectDto), "password");
    }
}
