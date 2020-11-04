package com.dna.dev.secretstash.model;

import java.time.LocalDateTime;

public class ErrorMessage {

    private String description;
    private LocalDateTime localDateTime;

    public ErrorMessage(String description, LocalDateTime localDateTime) {
        this.description = description;
        this.localDateTime = localDateTime;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public LocalDateTime getLocalDateTime() {
        return localDateTime;
    }

    public void setLocalDateTime(LocalDateTime localDateTime) {
        this.localDateTime = localDateTime;
    }
}
