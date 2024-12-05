package com.vishalraj.restaurantlisting.controller;

import com.vishalraj.restaurantlisting.dto.RestaurantDTO;
import com.vishalraj.restaurantlisting.service.RestaurantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/restaurant")
public class RestaurantController {

    @Autowired
    RestaurantService restaurantService;

    @GetMapping("/fetchAllRestaurants")
    public ResponseEntity<List<RestaurantDTO>> fetchAllRestaurants(){
        List<RestaurantDTO> allRestaurants = restaurantService.findAllRestaurants();
        return new ResponseEntity<>(allRestaurants, HttpStatus.OK);
    }

    @PostMapping("/addRestaurant")
    public ResponseEntity<RestaurantDTO> addRestaurant(@RequestBody RestaurantDTO restaurantDTO){
        RestaurantDTO restaurantAdded = restaurantService.addRestaurantToDB(restaurantDTO);
        return new ResponseEntity<>(restaurantAdded,HttpStatus.CREATED);
    }

    @GetMapping("/fetchId/{id}")
    public ResponseEntity<RestaurantDTO> fetchRestaurantById(@PathVariable Integer id){
        return restaurantService.fetchRestaurantById(id);
    }
}
