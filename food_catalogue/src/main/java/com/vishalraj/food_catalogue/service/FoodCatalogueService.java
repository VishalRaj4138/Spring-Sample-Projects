package com.vishalraj.food_catalogue.service;

import com.vishalraj.food_catalogue.dto.FoodCataloguePage;
import com.vishalraj.food_catalogue.dto.FoodItemDTO;
import com.vishalraj.food_catalogue.dto.Restaurant;
import com.vishalraj.food_catalogue.entity.FoodItem;
//import com.vishalraj.food_catalogue.feign.RestaurantInterface;
import com.vishalraj.food_catalogue.mapper.FoodItemMapper;
import com.vishalraj.food_catalogue.repo.FoodItemRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class FoodCatalogueService {

    @Autowired
    FoodItemRepo foodItemRepo;

    @Autowired
    RestTemplate restTemplate;

//    @Autowired
//    RestaurantInterface restaurantInterface;

    public FoodItemDTO addFoodItem(FoodItemDTO foodItemDTO) {
        FoodItem foodItem = foodItemRepo.save(FoodItemMapper.INSTANCE.mapFoodItemDTOtoFoodItem(foodItemDTO));
        return FoodItemMapper.INSTANCE.mapFoodItemToFoodItemDTO(foodItem);
    }

    public FoodCataloguePage fetchFoodCataloguePageDetails(Integer restaurantId) {

        List<FoodItem> foodItemList = fetchFoodItemList(restaurantId);
        Restaurant restaurant = fetchRestaurantDetails(restaurantId);
        return createFoodCataloguePage(foodItemList, restaurant);

    }

    private FoodCataloguePage createFoodCataloguePage(List<FoodItem> foodItemList, Restaurant restaurant) {
        FoodCataloguePage foodCataloguePage = new FoodCataloguePage();
        foodCataloguePage.setFoodItemList(foodItemList);
        foodCataloguePage.setRestaurant(restaurant);
        return foodCataloguePage;
    }

    private Restaurant fetchRestaurantDetails(Integer restaurantId) {
//        return restaurantInterface.fetchRestaurantById(restaurantId).getBody();
        return restTemplate.getForObject("http://RESTAURANTLISTING/restaurant/fetchId/"+restaurantId, Restaurant.class);
    }

    private List<FoodItem> fetchFoodItemList(Integer restaurantId) {
        return foodItemRepo.findByRestaurantId(restaurantId);
    }
}
