package com.springboot.inventory.user.service;

import com.springboot.inventory.common.entity.User;
import com.springboot.inventory.common.enums.ResponseEnum;
import com.springboot.inventory.common.enums.TokenType;
import com.springboot.inventory.common.enums.UserRoleEnum;
import com.springboot.inventory.common.jwt.JwtProvider;
import com.springboot.inventory.common.util.redis.RedisRepository;
import com.springboot.inventory.common.util.redis.RefreshToken;
import com.springboot.inventory.user.dto.SignInResultDto;
import com.springboot.inventory.user.dto.SignUpResultDto;
import com.springboot.inventory.user.dto.UserInfoDto;
import com.springboot.inventory.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Struct;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    @Autowired
    private RedisRepository redisRepository;

    // 회원가입
    @Transactional
    @Override
    public SignUpResultDto signUp(String email, String password, String name, String tel, String team) {

        LOGGER.info("[UserServiceImpl - signUp]");

        if(userRepository.existsByEmail(email)) {
            throw new IllegalStateException("이미 존재하는 이메일입니다.");
        }
        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .username(name)
                .tel(tel)
                .team(team)
                .roles(UserRoleEnum.USER)
                .build();

        User savedUser = userRepository.save(user);
        SignUpResultDto signUpResultDto = new SignUpResultDto();

        LOGGER.info("[UserServiceImpl - signUp - savedUser]");
        if (!savedUser.getEmail().isEmpty()) {
            LOGGER.info("[savedUser - OK]");
            setSuccessResult(signUpResultDto);
        } else {
            LOGGER.info("[savedUser - FAIL]");
            setFailResult(signUpResultDto);
        }

        return signUpResultDto;
    }

    // 로그인
    @Transactional
    @Override
    public SignInResultDto signIn(String email, String password) throws RuntimeException {
        LOGGER.info("[UserServiceImpl - signIn]");
        User user = userRepository.getByEmail(email);

        if(!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException();
        }       // 로그인 실패 시

        getRefreshToken(user);

        String accessToken = jwtProvider.createToken(user.getEmail(), user.getRoles(), TokenType.ACCESS);

        SignInResultDto signInResultDto = SignInResultDto.builder()
                .token(accessToken)
                .build();

        setSuccessResult(signInResultDto);

        return signInResultDto;
    }

    // 로그아웃
    @Override
    @Transactional
    public ResponseEntity<String> logOut(String email, HttpServletRequest request, HttpServletResponse response) {
        deleteAllCookies(request, response);
        deleteRefreshToken(email);
        return ResponseEntity.ok("로그아웃 성공");
    }



    // 권한 변경
    @Override
    @Transactional
    public ResponseEntity<String> grantRole(String email, UserRoleEnum roles) {
        User user = userRepository.getByEmail(email);

        if (user != null) {
            UserRoleEnum currentRole = user.getRoles();

            // 현재 권한이 USER이면 MANAGER로, MANAGER이면 USER로 변경
            UserRoleEnum newRole = (currentRole == UserRoleEnum.USER) ? UserRoleEnum.MANAGER : UserRoleEnum.USER;

            user.changeRole(newRole);
            return ResponseEntity.ok("권한 부여가 완료되었습니다.");
        } else {
            // 사용자를 찾을 수 없을 때 처리
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("사용자를 찾을 수 없습니다.");
        }
    }
    // USER 찾기
    public List<User> getUsersByUserRole() {
        // 역할(role)이 USER인 사용자만 필터링하여 반환
        return userRepository.findByRoles(UserRoleEnum.USER);
    }
    @Transactional
    public List<UserInfoDto> findAllUser() { // 모든 USER를 보여준다.(MANAGER,ADMIN)
        List<User> userList = getUsersByUserRole();
        List<UserInfoDto> userDtoList = new ArrayList<>();

        for (User user : userList) {
            userDtoList.add(UserInfoDto.toDto(user));
        }

        return userDtoList;
    }

    // 이메일 중복 확인
    public boolean doublecheck(String email) {
        // 이메일 중복 확인: 데이터베이스에서 해당 이메일로 사용자를 찾아봄
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            // 이메일이 이미 존재하는 경우
            System.out.println("중복된 값입니다. 다시 입력해주세요.");
            return true;
        } else {
            // 이메일이 존재하지 않는 경우
            System.out.println("사용할 수 있는 이메일입니다.");
            return false;
        }
    }

    // 개인 조회
    @Override
    @Transactional
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    @Transactional
    public void deleteUser(String email, HttpServletRequest request, HttpServletResponse response) {
        userRepository.deleteByEmail(email);
        deleteRefreshToken(email);
        deleteAllCookies(request, response);

    }

    @Override
    @Transactional
    public void delete(String email){
        userRepository.deleteByEmail(email);
        deleteRefreshToken(email);
    }
    // 팀 설정 업데이트하기
    @Transactional
    public void updateTeam(String email, String newTeam) {
        Optional<User> byUser = userRepository.findByEmail(email);
        if(byUser.isPresent()){
            User user = byUser.get();
            user.updateTeam(newTeam);
            userRepository.save(user);
        } else {
            throw new RuntimeException("User not found with email: " + email);
        }
    }

    // 전체 유저 조회(ADMIN용)
    @Override
    public List<UserInfoDto> findAllUserForAdmin(String adminEmail) {
        List<User> userList = userRepository.findAll();
        List<UserInfoDto> userDtoList = new ArrayList<>();

        for (User user : userList) {
            // 현재 유저를 제외한 다른 유저만 추가
            if (!user.getEmail().equals(adminEmail)) {
                userDtoList.add(UserInfoDto.toDto(user));
            }
        }
        return userDtoList;
    }

    private void deleteRefreshToken(String email) {
        Optional<RefreshToken> refreshToken =redisRepository.findById(email);
        if(refreshToken.isPresent()){
            redisRepository.deleteById(email);
        }
    }

    private void deleteAllCookies(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                ResponseCookie responseCookie = ResponseCookie.from(cookie.getName(), null).
                        path("/").
                        httpOnly(true).
                        sameSite("None").
                        secure(true).
                        maxAge(1).
                        build();
                response.addHeader("Set-Cookie", responseCookie.toString());
            }
        }
    }



    private void setSuccessResult(SignUpResultDto result) {
        result.setSuccess(true);
        result.setCode(ResponseEnum.SUCCESS.getCode());
        result.setMsg(ResponseEnum.SUCCESS.getMsg());
    }

    private void setFailResult(SignUpResultDto result) {
        result.setSuccess(false);
        result.setCode(ResponseEnum.FAIL.getCode());
        result.setMsg(ResponseEnum.FAIL.getMsg());
    }

    private void getRefreshToken(User user) {
        String createdRefreshToken = jwtProvider.createToken(user.getEmail(), user.getRoles(), TokenType.REFRESH);
        Optional<RefreshToken> refreshToken = redisRepository.findById(user.getEmail());
        long expiration = jwtProvider.REFRESH_TOKEN_TIME;

        if(refreshToken.isPresent()) {
            RefreshToken savedRefreshToken = refreshToken.get().updateToken(createdRefreshToken, expiration);
            redisRepository.save(savedRefreshToken);
        } else {
            RefreshToken refreshToSave = RefreshToken.builder()
                    .email(user.getEmail())
                    .refreshToken(createdRefreshToken)
                    .expiration(expiration)
                    .build();
            redisRepository.save(refreshToSave);
        }
    }

}
