package com.vishalraj.food_catalogue.mapper;

import com.vishalraj.food_catalogue.dto.FoodItemDTO;
import com.vishalraj.food_catalogue.entity.FoodItem;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface FoodItemMapper {

    FoodItemMapper INSTANCE = Mappers.getMapper(FoodItemMapper.class);

    FoodItem mapFoodItemDTOtoFoodItem(FoodItemDTO foodItemDTO);

    FoodItemDTO mapFoodItemToFoodItemDTO(FoodItem foodItem);
}
