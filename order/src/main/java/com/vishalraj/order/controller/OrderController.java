package com.vishalraj.order.controller;

import com.vishalraj.order.dto.OrderDTO;
import com.vishalraj.order.dto.OrderRequestDTO;
import com.vishalraj.order.dto.OrderRequestDTOMy;
import com.vishalraj.order.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/order")
public class OrderController {

    @Autowired
    OrderService orderService;

    @PostMapping("/saveOrder")
    public ResponseEntity<OrderDTO> saveOrder(@RequestBody OrderRequestDTO orderDetails){
        OrderDTO orderDTO = orderService.saveOrderInDB(orderDetails);
        return new ResponseEntity<>(orderDTO, HttpStatus.CREATED);
    }

    @PostMapping("/saveOrder1")
    public ResponseEntity<OrderDTO> saveOrder1(@RequestBody OrderRequestDTOMy orderDetails){
        OrderDTO orderDTO = orderService.saveOrderInDB1(orderDetails);
        return new ResponseEntity<>(orderDTO, HttpStatus.CREATED);
    }
}
