package com.intern.onesync.config;

import java.io.IOException;


import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTFilter extends OncePerRequestFilter { //요청당 한번만 실행되면 됨
    private final JWTUtil jwtUtil;  //JWT검증 위하여 주입

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 특정 경로들에 대해 필터 로직을 건너뛰도록 설정
        if (request.getMethod().equals(HttpMethod.OPTIONS.name())) {
            // OPTIONS 요청일 경우 필터 처리를 건너뛰고 다음 필터로 진행
            filterChain.doFilter(request, response);
            return;
        }
        String path = request.getRequestURI();
        if (path.startsWith("/health-check") || path.startsWith("/security-check")
                || path.startsWith("/auth/reissue") || path.startsWith("/login") || path.startsWith("/reissue")
                || path.matches("/api/v1/client") || path.matches("/api/v1/member") || path.matches("/oauth2/authorization/*")||path.matches("process-login")
                || path.startsWith("/auth/issue/mobile")||path.matches("/login")) {
            System.out.println("jwt필터 통과로직");
            filterChain.doFilter(request, response);
            return;
        }

        // 헤더에서 authorization키에 담긴 토큰을 꺼냄
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        //토큰꺼내기
        String accessToken = authorization.split(" ")[1];
        System.out.println("accessToken = " + accessToken);

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {

            filterChain.doFilter(request, response);

            return;
        }
        System.out.println("여기까진 들어옴");
        //토큰 소멸 시간 검증

        //토큰에서 username과 cleintId 획득
        String memberUsername = jwtUtil.getSubject(accessToken).toString();
        String clientId=jwtUtil.getAudience(accessToken).toString();

        log.info("[*] Current User: " + memberUsername);
        log.info("[*] Current User ClientId: " + clientId);



        CustomAuthenticationToken authToken = new CustomAuthenticationToken(
                memberUsername,
                null,
                clientId,
                null // 권한 정보는 필요 시 추가
        );

        SecurityContextHolder.getContext().setAuthentication(authToken); //authentication객체 저장

        filterChain.doFilter(request, response);
        //
    }
}
