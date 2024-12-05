package com.vishalraj.order.entity;

import com.vishalraj.order.dto.FoodItemsDTO;
import com.vishalraj.order.dto.RestaurantDTO;
import com.vishalraj.order.dto.UserDTO;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Document("order")
public class Order {

    private Integer orderId;
    private List<FoodItemsDTO> foodItemsList;
    private UserDTO user;
    private RestaurantDTO restaurant;
}
