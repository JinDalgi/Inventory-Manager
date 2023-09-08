package com.springboot.inventory.user.dto;

import lombok.Getter;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Getter
public class ChangePasswordDto {

    @NotNull
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@#$%^&+=!])(?!.*\\s).{8,16}$",
            message = "8~16자, 최소 하나의 문자, 하나의 숫자, 하나의 특수 문자, 공백 없음")
    private String password;
}
