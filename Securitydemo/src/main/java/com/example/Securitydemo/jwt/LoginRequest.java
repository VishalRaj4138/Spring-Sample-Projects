package com.example.Securitydemo.jwt;

//This is just a model or DOA class telling about te details of the user which would be used to pass user details while creating Token
public class LoginRequest {
    private String username;
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
