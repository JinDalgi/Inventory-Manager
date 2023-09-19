package com.springboot.inventory.user.controller;

import com.springboot.inventory.common.entity.User;
import com.springboot.inventory.common.security.UserDetailsImpl;
import com.springboot.inventory.user.dto.SignInResultDto;
import com.springboot.inventory.user.dto.SignUpResultDto;
import com.springboot.inventory.user.dto.SigninRequestDTO;
import com.springboot.inventory.user.service.UserService;
import io.swagger.annotations.ApiParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/sign-api/")
public class UserRestController {

    private final Logger LOGGER = LoggerFactory.getLogger(UserRestController.class);
    private final UserService userService;

    public UserRestController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/custom-login")
    @ResponseBody
    public ResponseEntity<String> signIn(@RequestBody SigninRequestDTO signinRequestDTO, HttpServletResponse response) throws UnsupportedEncodingException {
        LOGGER.info("[UserRestController - signIn]");

        String email = signinRequestDTO.getUsername();

        String password = signinRequestDTO.getPassword();


        SignInResultDto signInResultDto = userService.signIn(email, password);

        String token = signInResultDto.getToken();

        Cookie cookie = new Cookie("Authorization", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        System.out.println(response);

        return ResponseEntity.ok("로그인 성공");
    }


    @PostMapping(value = "/sign-up")
    public SignUpResultDto signUp(@ApiParam(value = "Email", required = true) @RequestParam String email,
                                  @ApiParam(value = "비밀번호", required = true) @RequestParam String password,
                                  @ApiParam(value = "이름", required = true) @RequestParam String username,
                                  @ApiParam(value = "전화번호", required = true) @RequestParam String tel,
                                  HttpServletResponse response) {
        LOGGER.info("[UserRestController - signUp]");
        SignUpResultDto signUpResultDto = userService.signUp(email, password, username, tel);
        LOGGER.info("[UserRestController - signUp 완료.]");

        // 회원가입이 성공한 경우, 메인 페이지로 리다이렉트
        if (signUpResultDto.isSuccess()) {
            try {
                response.sendRedirect("/index");
            } catch (IOException e) {
                // 리다이렉션 실패 시 처리
                e.printStackTrace();
            }
        }

        return signUpResultDto;
    }

    // 로그아웃
    @GetMapping("/logOut")
    public ResponseEntity<Void> logOut(@AuthenticationPrincipal UserDetailsImpl userDetails,
                                       HttpServletRequest request,
                                       HttpServletResponse response) throws IOException, URISyntaxException {
        userService.logOut(userDetails.getUsername(), request, response);
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .location(new URI("/index"))
                .build();
    }

    // 회원 조회
    @GetMapping("/finduser/{email}")
    public ResponseEntity<?> findByEmail(@PathVariable("email") String email) {
        Optional<User> user = userService.findByEmail(email);
        if (user.isPresent()) {
            return ResponseEntity.ok(user.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    // 모든 회원
    @GetMapping("/ManagerPage")
    public ResponseEntity<List<User>> findAllUser() {
        List<User> userList = userService.findAllUser();
        return ResponseEntity.status(HttpStatus.OK).body(userList);
    }

    // 권한 부여
    @PutMapping("/roles/{email}")
    public ResponseEntity<String> grantRole(@PathVariable String email,
                                            @AuthenticationPrincipal UserDetailsImpl userDetails) {
        return userService.grantRole(email, userDetails.getUser().getRoles());
    }

}
