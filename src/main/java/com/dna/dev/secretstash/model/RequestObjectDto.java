package com.dna.dev.secretstash.model;

import java.util.Objects;

public class RequestObjectDto {

    private String password;

    public RequestObjectDto() {
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RequestObjectDto that = (RequestObjectDto) o;
        return Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(password);
    }
}
