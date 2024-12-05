package com.vishalraj.order.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class OrderRequestDTOMy {

    private List<FoodItemsDTO> foodItemsList;
    private Integer userId;
    private Integer restaurantId;
}
