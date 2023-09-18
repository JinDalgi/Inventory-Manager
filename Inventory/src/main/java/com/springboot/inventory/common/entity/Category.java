package com.springboot.inventory.common.entity;

import com.springboot.inventory.common.enums.LargeCategory;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.SQLDelete;

import javax.persistence.*;

@Getter
@Setter
@Entity
@NoArgsConstructor
@SQLDelete(sql = "UPDATE category SET deleted = true WHERE id = ?")
public class Category {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long categoryId;

    @Column(unique = true)
    private String categoryName;

    @Enumerated(EnumType.STRING)
    private LargeCategory largeCategory;

    private Boolean deleted;


    @Builder
    public Category(String categoryName, LargeCategory largeCategory, Boolean deleted) {
        this.categoryName = categoryName;
        this.largeCategory = largeCategory;
        this.deleted = deleted;
    }
}