package com.vishalraj.order.service;

import com.vishalraj.order.dto.*;
import com.vishalraj.order.entity.Order;
import com.vishalraj.order.mapper.OrderMapper;
import com.vishalraj.order.repo.OrderRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class OrderService {

    @Autowired
    OrderRepo orderRepo;

    @Autowired
    SequenceGenerator sequenceGenerator;

    @Autowired
    RestTemplate restTemplate;

    public OrderDTO saveOrderInDB(OrderRequestDTO orderDetails) {
        Integer newOrderId = sequenceGenerator.generateNextOrderId();
        UserDTO userDTO = fetchUserDetails(orderDetails.getUserId());
        Order orderToBeSaved =new Order(newOrderId, orderDetails.getFoodItemsList(), userDTO, orderDetails.getRestaurant());

        orderRepo.save(orderToBeSaved);
        return OrderMapper.INSTANCE.mapOrderToOrderDTO(orderToBeSaved);
    }

    private UserDTO fetchUserDetails(Integer userId) {
        return restTemplate.getForObject("http://USERINFORMATION/user/userId/" + userId,UserDTO.class);
    }

    public OrderDTO saveOrderInDB1(OrderRequestDTOMy orderDetails) {
        Integer newOrderId = sequenceGenerator.generateNextOrderId();
        UserDTO userDTO = fetchUserDetails(orderDetails.getUserId());
        RestaurantDTO restaurantDTO = fetchRestaurantDetails(orderDetails.getRestaurantId());
        Order orderToBeSaved =new Order(newOrderId, orderDetails.getFoodItemsList(), userDTO, restaurantDTO);

        orderRepo.save(orderToBeSaved);
        return OrderMapper.INSTANCE.mapOrderToOrderDTO(orderToBeSaved);
    }

    private RestaurantDTO fetchRestaurantDetails(Integer restaurantId) {
        return restTemplate.getForObject("http://RESTAURANTLISTING/restaurant/fetchId/"+restaurantId,RestaurantDTO.class);
    }
}
