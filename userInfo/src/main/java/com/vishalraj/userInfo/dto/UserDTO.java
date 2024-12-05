package com.vishalraj.userInfo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserDTO {

    private int id;
    private String userName;
    private String userPassword;
    private String address;
    private String city;
}
