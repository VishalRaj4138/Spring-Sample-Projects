package com.vishalraj.userInfo.controller;


import com.vishalraj.userInfo.dto.UserDTO;
import com.vishalraj.userInfo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    UserService userService;

    @PostMapping("/addUser")
    public ResponseEntity<UserDTO> addUser(@RequestBody UserDTO userDTO){
        UserDTO savedUser = userService.addUser(userDTO);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);
    }

    @GetMapping("/userId/{id}")
    public ResponseEntity<UserDTO> findUserById(@PathVariable Integer id){
        return userService.findUserById(id);
    }
}
