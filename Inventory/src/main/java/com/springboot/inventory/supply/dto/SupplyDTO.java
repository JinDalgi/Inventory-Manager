package com.springboot.inventory.supply.dto;

import com.springboot.inventory.common.entity.Category;
import com.springboot.inventory.common.enums.LargeCategory;
import com.springboot.inventory.common.enums.SupplyStatusEnum;
import com.springboot.inventory.common.enums.UserRole;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class SupplyDTO {

    private String serialNum;
    private String modelContent;
    private int amount;
    private String modelName;
    private SupplyStatusEnum status;

    //이미지
    private String image;
    private String imagePath;
    private MultipartFile multipartFile;

    //카테고리
    private Category category;
    private LargeCategory largeCategory;
    private String categoryName;

    //사용자
    private Long userId;
    private UserRole userRole;
    private Long teamId;

}
