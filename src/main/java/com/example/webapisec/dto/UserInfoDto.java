package com.example.webapisec.dto;

public class UserInfoDto {
    private String username;
    private String password;

    public UserInfoDto() {
    }

    public UserInfoDto(String username, String password) {
        this.username = username;
        this.password = password;
    }

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
