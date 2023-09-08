package com.springboot.inventory.common.entity;

import com.springboot.inventory.common.enums.UserRoleEnum;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity(name = "users")
@NoArgsConstructor
@Getter
//@SQLDelete(sql = "UPDATE users SET deleted = true, ")
public class User extends Timestamped {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 아이디
    @Column(nullable = false, unique = true)
    private String username;

    private String password;

    // 유저 정보
    private String name;
    private String tel;


    // 토큰
//    @Column(nullable = false)
//    private String accessToken;

    @Enumerated(value = EnumType.STRING)
    private UserRoleEnum role;

    @Column(nullable = false)
    private Boolean alarm;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id")
    private Group group;

    @Column(nullable = false)
    private Boolean deleted;

    public User(String username, String password, String name, String tel,
                UserRoleEnum role, Group group, Boolean deleted) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.tel = tel;
        this.role = role;
        this.group = group;
        this.deleted = deleted;
    }

    public void update(String name, Group group, String tel, String password) {
        this.name = name;
        this.group = group;
        this.tel = tel;
        this.password = password;
    }

    public void changePassword(String password) {
        this.password = password;
    }

//    public void refreshToken(String accessToken) {
//        this.accessToken = accessToken;
//    }

    public void changeRole(UserRoleEnum role) {
        // 부여하는 권한을 가지고 있는 경우, 권한을 취소할 수 있음
        this.role = this.role == role ? UserRoleEnum.USER : role;
    }
}
