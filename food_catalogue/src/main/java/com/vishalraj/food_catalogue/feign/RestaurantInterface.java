//package com.vishalraj.food_catalogue.feign;
//
//import com.vishalraj.food_catalogue.dto.Restaurant;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PathVariable;
//
//@FeignClient(value = "RESTAURANT-LISTING", url = "http://localhost:9091/restaurant")
//public interface RestaurantInterface {
//
//    @GetMapping("/fetchId/{id}")
//    public ResponseEntity<Restaurant> fetchRestaurantById(@PathVariable Integer id);
//}
