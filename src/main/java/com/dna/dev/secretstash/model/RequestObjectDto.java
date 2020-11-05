package com.dna.dev.secretstash.model;

import com.fasterxml.jackson.annotation.JsonFilter;

import java.util.Objects;

@JsonFilter("BeanFilter")
public class RequestObjectDto {

    private String password;
    private String salt;

    public RequestObjectDto() {
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
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
