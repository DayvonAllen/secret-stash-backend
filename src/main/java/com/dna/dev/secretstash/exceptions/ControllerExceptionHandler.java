package com.dna.dev.secretstash.exceptions;

import com.dna.dev.secretstash.model.ErrorMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class ControllerExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage> exception(Exception e){
        return new ResponseEntity<>(new ErrorMessage("Couldn't generate token.", LocalDateTime.now()), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(SecretStashException.class)
    public ResponseEntity<ErrorMessage> exception(SecretStashException e){
        return new ResponseEntity<>(new ErrorMessage(e.getMessage(), LocalDateTime.now()), HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
