package com.vishalraj.food_catalogue.controller;

import com.vishalraj.food_catalogue.dto.FoodCataloguePage;
import com.vishalraj.food_catalogue.dto.FoodItemDTO;
import com.vishalraj.food_catalogue.service.FoodCatalogueService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/foodCatalogue")
public class FoodCatalogueController {

    @Autowired
    FoodCatalogueService foodCatalogueService;

    @PostMapping("/addFoodItem")
    public ResponseEntity<FoodItemDTO> addFoodItem(@RequestBody FoodItemDTO foodItemDTO){
        FoodItemDTO savedFoodItem = foodCatalogueService.addFoodItem(foodItemDTO);
        return new ResponseEntity<>(savedFoodItem, HttpStatus.CREATED);
    }

    @GetMapping("/fetchRestaurantFoodItemsById/{id}")
    public ResponseEntity<FoodCataloguePage> foodRestaurantDetailsWithFoodMenu(@PathVariable Integer id){
        FoodCataloguePage foodCataloguePage = foodCatalogueService.fetchFoodCataloguePageDetails(id);
        return new ResponseEntity<>(foodCataloguePage,HttpStatus.OK);
    }
}
