package com.vishalraj.order.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class OrderRequestDTO {

    private List<FoodItemsDTO> foodItemsList;
    private Integer userId;
    private RestaurantDTO restaurant;
}
