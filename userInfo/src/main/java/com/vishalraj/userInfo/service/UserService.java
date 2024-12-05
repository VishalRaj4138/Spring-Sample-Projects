package com.vishalraj.userInfo.service;

import com.vishalraj.userInfo.dto.UserDTO;
import com.vishalraj.userInfo.entity.User;
import com.vishalraj.userInfo.mapper.UserMapper;
import com.vishalraj.userInfo.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    UserRepo userRepo;

    public UserDTO addUser(UserDTO userDTO) {
        User savedUser = userRepo.save(UserMapper.INSTANCE.mapUserDTOtoUser(userDTO));
        return UserMapper.INSTANCE.mapUserToUserDTO(savedUser);
    }

    public ResponseEntity<UserDTO> findUserById(Integer id) {
        Optional<User> user = userRepo.findById(id);
        if(user.isPresent())
            return new ResponseEntity<>(UserMapper.INSTANCE.mapUserToUserDTO(user.get()), HttpStatus.FOUND);
        return new ResponseEntity<>(null,HttpStatus.NOT_FOUND);
    }
}
