package com.springboot.inventory.common.entity;

import com.springboot.inventory.common.enums.RequestTypeEnum;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "supply")
@Getter
@Setter
public class Supply extends TimeStamp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long supplyId;

    @Column(nullable = false)
    private Integer amount;

    @Column(nullable = false)
    private String modelName;

    @Enumerated(value = EnumType.STRING)
    private RequestTypeEnum state;

}
