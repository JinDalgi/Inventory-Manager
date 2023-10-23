package com.springboot.inventory.common.jwt;

import com.springboot.inventory.common.enums.TokenState;
import com.springboot.inventory.common.enums.TokenType;
import com.springboot.inventory.common.enums.UserRoleEnum;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String accessToken = null;
        String refreshToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie == null) {
                    continue;
                }
                if (cookie.getName().equals(JwtProvider.AUTHORIZATION_HEADER)) {
                    accessToken = jwtProvider.resolveToken(cookie);
                } else if (cookie.getName().equals(JwtProvider.REFRESH_HEADER)) {
                    refreshToken = jwtProvider.resolveToken(cookie);
                }
            }
        }

        if (accessToken != null) {
            TokenState state = jwtProvider.validateToken(accessToken);
            if (TokenState.VAILD.equals(state)) {
                setAuthentication(jwtProvider.getUserInfoFromToken(accessToken).getSubject());
            } else if (TokenState.EXPIRED.equals(state)) {
                if (jwtProvider.validateRefreshToken(refreshToken)) {
                    Claims userInfo = jwtProvider.getUserInfoFromToken(refreshToken);
                    String email = userInfo.getSubject();
                    String createdAccessToken = jwtProvider.createToken(email, UserRoleEnum.USER, TokenType.ACCESS);
                    ResponseCookie cookie = ResponseCookie.from(
                                    JwtProvider.AUTHORIZATION_HEADER,
                                    URLEncoder.encode(createdAccessToken, "UTF-8"))
                            .path("/")
                            .httpOnly(true)
                            .sameSite("None")
                            .secure(true)
                            .maxAge(JwtProvider.ACCESS_TOKEN_TIME)
                            .build();
                    response.addHeader("Set-Cookie", cookie.toString());
                    setAuthentication(email);
                }
            }
        } else if (refreshToken != null) {
            if (jwtProvider.validateRefreshToken(refreshToken)) {
                setAuthentication(jwtProvider.getUserInfoFromToken(refreshToken).getSubject());
            }
        }
        filterChain.doFilter(request, response);
    }

    public void setAuthentication(String email) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = jwtProvider.createAuthentication(email);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    public void jwtExceptionHandler(HttpServletResponse response, String message, HttpStatus httpStatus) {
        response.setStatus(httpStatus.value());
        response.setContentType("application/json;charset=UTF-8");
        try {
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}