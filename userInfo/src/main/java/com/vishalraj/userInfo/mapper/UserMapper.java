package com.vishalraj.userInfo.mapper;

import com.vishalraj.userInfo.dto.UserDTO;
import com.vishalraj.userInfo.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface UserMapper {

    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    User mapUserDTOtoUser(UserDTO userDTO);

    UserDTO mapUserToUserDTO(User user);


}
