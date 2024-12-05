package com.vishalraj.order.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class OrderDTO {
    private Integer orderId;
    private List<FoodItemsDTO> foodItemsList;
    private UserDTO user;
    private RestaurantDTO restaurant;
}
