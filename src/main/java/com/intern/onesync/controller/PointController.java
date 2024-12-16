package com.intern.onesync.controller;

import com.intern.onesync.config.CustomAuthenticationToken;
import com.intern.onesync.dto.BasicJoinDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/point")
@RequiredArgsConstructor
public class PointController {

    @Operation(summary = "테스트코드")
    @ApiResponse(responseCode = "200", description = "토큰 분해 완료")
    @PostMapping("/test")
    public ResponseEntity<String> join() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomAuthenticationToken customAuth = (CustomAuthenticationToken) authentication;
        String username = (String) customAuth.getPrincipal();
        String clientId = customAuth.getClientId();
        return ResponseEntity.ok().body("username : "+ username+"\nclientId : "+ clientId );
    }
}
