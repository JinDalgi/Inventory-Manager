package com.springboot.inventory.common.enums;

import lombok.Getter;
@Getter
public enum UserRoleEnum {
    USER(Authority.USER), // 사용자 권한
    ADMIN(Authority.ADMIN), // 관리자 권한
    MASTER(Authority.MASTER);// 마스터 권한

    private final String authority;


    UserRoleEnum(String authority) {
        this.authority = authority;
    }

    public static class Authority {
        public static final String USER = "ROLE_USER";  // 유저
        public static final String ADMIN = "ROLE_ADMIN";    // 비품 총괄 관리자
        public static final String MASTER = "ROLE_MASTER";  // 마스터
    }
}